@testable import Citadel
import NIO
@preconcurrency import NIOSSH
import XCTest
import Foundation

@available(macOS 15.0, *)
final class WithExecTests: XCTestCase {

    // MARK: - Helpers

    private struct TestTimeout: Error {}

    private actor StderrLifecycle {
        private let receiptStream: AsyncStream<Void>
        private let receiptContinuation: AsyncStream<Void>.Continuation
        private var writerClosed = false

        init() {
            (receiptStream, receiptContinuation) = AsyncStream<Void>.makeStream()
        }

        func waitForReceipt() async {
            for await _ in receiptStream {
                return
            }
        }

        func recordReceipt() -> Bool {
            let receivedBeforeEOF = !writerClosed
            receiptContinuation.yield()
            receiptContinuation.finish()
            return receivedBeforeEOF
        }

        func markWriterClosed() {
            writerClosed = true
        }
    }

    private actor FailureLifecycle {
        private let stream: AsyncStream<Void>
        private let continuation: AsyncStream<Void>.Continuation

        init() {
            (stream, continuation) = AsyncStream<Void>.makeStream()
        }

        func waitForFailure() async {
            for await _ in stream {
                return
            }
        }

        func triggerFailure() {
            continuation.yield()
            continuation.finish()
        }
    }

    /// Bridges an NIO future without trapping a cancelled structured task.
    private static func getRespectingCancellation<Value: Sendable>(
        _ future: EventLoopFuture<Value>
    ) async throws -> Value {
        let proxy = future.eventLoop.makePromise(of: Value.self)
        future.cascade(to: proxy)

        return try await withTaskCancellationHandler {
            try await proxy.futureResult.get()
        } onCancel: {
            proxy.fail(CancellationError())
        }
    }

    private func runTest(
        timeout: Duration = .seconds(5),
        perform: @escaping (SSHServer, SSHClient) async throws -> Void
    ) async throws {
        let authDelegate = AuthDelegate(supportedAuthenticationMethods: .password) { request, promise in
            switch request.request {
            case .password(.init(password: "test")) where request.username == "citadel":
                promise.succeed(.success)
            default:
                promise.succeed(.failure)
            }
        }
        let server = try await SSHServer.host(
            host: "localhost",
            port: 0,
            hostKeys: [NIOSSHPrivateKey(p521Key: .init())],
            authenticationDelegate: authDelegate
        )

        let port = try XCTUnwrap(server.channel.localAddress?.port)

        let client = try await SSHClient.connect(
            host: "localhost",
            port: port,
            authenticationMethod: .passwordBased(username: "citadel", password: "test"),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )

        defer {
            Task { try? await server.close() }
        }

        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                group.addTask {
                    try await perform(server, client)
                }
                group.addTask {
                    try await Task.sleep(for: timeout)
                    throw TestTimeout()
                }
                // First to finish wins; cancel the other
                try await group.next()
                group.cancelAll()
            }
        } catch is TestTimeout {
            XCTFail("Test timed out after \(timeout)")
        } catch let error as ChannelError where error == .alreadyClosed {
            // Server-initiated channel close can race with client close in withExec
        }

        do {
            try await client.close()
        } catch let error as ChannelError where error == .alreadyClosed {
            // Already cleaned up
        }
    }

    // MARK: - Tests

    /// Server writes known data to stdout; client receives it tagged as `.stdout`.
    func testWithExecReceivesStdout() async throws {
        final class Exec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                DispatchQueue.global().async {
                    let handle = outputHandler.stdoutPipe.fileHandleForWriting
                    handle.write(Data("hello stdout".utf8))
                    try? handle.close()
                    // Let NIO drain the pipe before succeed triggers pipeChannel.close
                    Thread.sleep(forTimeInterval: 0.3)
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = Exec()
            server.enableExec(withDelegate: execDelegate)

            try await client.withExec("test") { inbound, _ in
                var collected = ByteBuffer()
                for try await chunk in inbound {
                    switch chunk {
                    case .stdout(let buf):
                        collected.writeImmutableBuffer(buf)
                    case .stderr:
                        XCTFail("Expected only stdout data")
                    }
                }
                XCTAssertEqual(String(buffer: collected), "hello stdout")
            }
        }
    }

    /// Client writes data via outbound and server writes back a response on stdout.
    /// Verifies both directions of the exec channel work in a single session.
    func testWithExecBidirectionalIO() async throws {
        final class Exec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            var receivedCommand: String?
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                receivedCommand = command
                DispatchQueue.global().async {
                    // Write a response on stdout (independent of stdin)
                    let output = outputHandler.stdoutPipe.fileHandleForWriting
                    output.write(Data("response from server".utf8))
                    try? output.close()
                    // Let NIO drain the pipe before succeed triggers pipeChannel.close
                    Thread.sleep(forTimeInterval: 0.3)
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = Exec()
            server.enableExec(withDelegate: execDelegate)

            try await client.withExec("my-command") { inbound, outbound in
                // Client writes to stdin (verifies write doesn't crash)
                try await outbound.write(ByteBuffer(string: "request from client"))

                // Client reads stdout response
                var collected = ByteBuffer()
                for try await chunk in inbound {
                    if case .stdout(let buf) = chunk {
                        collected.writeImmutableBuffer(buf)
                    }
                }
                XCTAssertEqual(String(buffer: collected), "response from server")
            }

            // Verify the command was forwarded correctly
            XCTAssertEqual(execDelegate.receivedCommand, "my-command")
        }
    }

    /// Binary data (all 256 byte values) is sent from server to client without mangling.
    func testWithExecBinaryData() async throws {
        let binaryPayload = Data(0...255)

        final class BinaryExec: ExecDelegate, @unchecked Sendable {
            let payload: Data
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            init(payload: Data) { self.payload = payload }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                let payload = self.payload
                DispatchQueue.global().async {
                    let output = outputHandler.stdoutPipe.fileHandleForWriting
                    output.write(payload)
                    try? output.close()
                    // Let NIO drain the pipe before succeed triggers pipeChannel.close
                    Thread.sleep(forTimeInterval: 0.3)
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = BinaryExec(payload: binaryPayload)
            server.enableExec(withDelegate: execDelegate)

            try await client.withExec("cat") { inbound, _ in
                var collected = ByteBuffer()
                for try await chunk in inbound {
                    if case .stdout(let buf) = chunk {
                        collected.writeImmutableBuffer(buf)
                    }
                }
                XCTAssertEqual(collected.readableBytes, 256)
                XCTAssertEqual(collected.readBytes(length: 256), Array(binaryPayload))
            }
        }
    }

    /// Server writes to stderr pipe; client receives data tagged as `.stderr`.
    func testWithExecReceivesStderr() async throws {
        final class Exec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                DispatchQueue.global().async {
                    let handle = outputHandler.stderrPipe.fileHandleForWriting
                    handle.write(Data("error output".utf8))
                    try? handle.close()
                    try? outputHandler.stdoutPipe.fileHandleForWriting.close()
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = Exec()
            server.enableExec(withDelegate: execDelegate)

            try await client.withExec("test") { inbound, _ in
                var collected = ByteBuffer()
                for try await chunk in inbound {
                    switch chunk {
                    case .stderr(let buf):
                        collected.writeImmutableBuffer(buf)
                    case .stdout:
                        break
                    }
                }
                XCTAssertEqual(String(buffer: collected), "error output")
            }
        }
    }

    /// Stderr is forwarded as it is produced rather than being buffered until
    /// the writer closes its end of the pipe.
    func testWithExecStreamsStderrBeforeEOF() async throws {
        final class StreamingExec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }

            let lifecycle: StderrLifecycle

            init(lifecycle: StderrLifecycle) {
                self.lifecycle = lifecycle
            }

            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}

            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                let lifecycle = self.lifecycle
                Task {
                    let stderr = outputHandler.stderrPipe.fileHandleForWriting
                    stderr.write(Data("streamed stderr".utf8))
                    try? outputHandler.stdoutPipe.fileHandleForWriting.close()

                    // Wait for the client to receive the chunk. The timeout lets
                    // detached read-to-EOF implementations finish so the test
                    // fails cleanly instead of leaving a stuck task.
                    await withTaskGroup(of: Void.self) { group in
                        group.addTask {
                            await lifecycle.waitForReceipt()
                        }
                        group.addTask {
                            try? await Task.sleep(for: .seconds(2))
                        }
                        await group.next()
                        group.cancelAll()
                    }

                    await lifecycle.markWriterClosed()
                    try? stderr.close()
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        let lifecycle = StderrLifecycle()

        try await runTest { server, client in
            server.enableExec(withDelegate: StreamingExec(lifecycle: lifecycle))

            try await client.withExec("test") { inbound, _ in
                var collected = ByteBuffer()
                var receivedBeforeEOF = false

                for try await chunk in inbound {
                    if case .stderr(let buffer) = chunk {
                        receivedBeforeEOF = await lifecycle.recordReceipt()
                        collected.writeImmutableBuffer(buffer)
                    }
                }

                XCTAssertTrue(receivedBeforeEOF)
                XCTAssertEqual(String(buffer: collected), "streamed stderr")
            }
        }
    }

    /// When the `perform` closure throws, the error propagates and the channel closes.
    func testWithExecClosesChannelOnError() async throws {
        struct TestError: Error, Equatable {}

        final class Exec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                DispatchQueue.global().async {
                    try? outputHandler.stdoutPipe.fileHandleForWriting.close()
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = Exec()
            server.enableExec(withDelegate: execDelegate)

            do {
                try await client.withExec("test") { _, _ in
                    throw TestError()
                }
                XCTFail("Expected error to propagate")
            } catch is TestError {
                // Expected
            }
        }
    }

    /// Once an exec request has succeeded, a later process failure is reported
    /// as an abnormal exit without a contradictory channel-failure reply. The
    /// terminal callback also closes Citadel's stderr writer when retained.
    func testExecFailureAfterChannelSuccessDoesNotSendChannelFailure() async throws {
        struct ProcessFailure: Error {}

        final class Exec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }

            let lifecycle: FailureLifecycle
            private var retainedOutputHandler: ExecOutputHandler?

            init(lifecycle: FailureLifecycle) {
                self.lifecycle = lifecycle
            }

            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}

            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                retainedOutputHandler = outputHandler
                let lifecycle = self.lifecycle
                Task {
                    await lifecycle.waitForFailure()
                    try? outputHandler.stdoutPipe.fileHandleForWriting.close()
                    outputHandler.fail(ProcessFailure())
                }
                return Ctx()
            }
        }

        final class ReplyRecorder: ChannelInboundHandler {
            typealias InboundIn = SSHChannelData

            let successPromise: EventLoopPromise<Void>
            let completionPromise: EventLoopPromise<(sawChannelFailure: Bool, exitStatus: Int?)>
            private var sawChannelFailure = false
            private var exitStatus: Int?

            init(eventLoop: EventLoop) {
                successPromise = eventLoop.makePromise()
                completionPromise = eventLoop.makePromise()
            }

            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                switch event {
                case is ChannelSuccessEvent:
                    successPromise.succeed()
                case is ChannelFailureEvent:
                    sawChannelFailure = true
                case let status as SSHChannelRequestEvent.ExitStatus:
                    exitStatus = status.exitStatus
                default:
                    context.fireUserInboundEventTriggered(event)
                }
            }

            func handlerRemoved(context: ChannelHandlerContext) {
                completionPromise.succeed((sawChannelFailure, exitStatus))
            }
        }

        let lifecycle = FailureLifecycle()

        try await runTest { server, client in
            let exec = Exec(lifecycle: lifecycle)
            server.enableExec(withDelegate: exec)

            let recorder = ReplyRecorder(eventLoop: client.eventLoop)
            let channel = try await Self.getRespectingCancellation(
                client.eventLoop.flatSubmit {
                    let createChannel = client.eventLoop.makePromise(of: Channel.self)
                    client.session.sshHandler.value.createChannel(createChannel) { channel, _ in
                        channel.pipeline.addHandler(recorder)
                    }
                    return createChannel.futureResult
                }
            )

            try await channel.triggerUserOutboundEvent(
                SSHChannelRequestEvent.ExecRequest(command: "test", wantReply: true)
            )
            try await Self.getRespectingCancellation(recorder.successPromise.futureResult)

            await lifecycle.triggerFailure()

            let result = try await Self.getRespectingCancellation(recorder.completionPromise.futureResult)
            XCTAssertFalse(result.sawChannelFailure)
            XCTAssertEqual(result.exitStatus, 255)
        }
    }

    // MARK: - ExecHandler infrastructure tests
    // These use public APIs other than withExec to show the fixes are
    // necessary at the server handler level, not specific to one client API.

    /// Stderr-only output is delivered via executeCommand.
    /// Exercises the writeAndFlush fix: without it, stderr data sits in the
    /// channel's write buffer and never reaches the client because nothing
    /// triggers a flush.
    func testExecuteCommandReceivesStderrOnly() async throws {
        final class StderrOnly: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                DispatchQueue.global().async {
                    let handle = outputHandler.stderrPipe.fileHandleForWriting
                    handle.write(Data("only on stderr".utf8))
                    try? handle.close()
                    // No stdout at all — close it immediately
                    try? outputHandler.stdoutPipe.fileHandleForWriting.close()
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = StderrOnly()
            server.enableExec(withDelegate: execDelegate)

            let result = try await client.executeCommand("test", mergeStreams: true)
            XCTAssertEqual(String(buffer: result), "only on stderr")
        }
    }

    /// Stderr arrives on the dedicated stderr stream of executeCommandPair.
    /// Same underlying fix: without writeAndFlush the data never flushes.
    func testExecuteCommandPairReceivesStderr() async throws {
        final class StderrExec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                DispatchQueue.global().async {
                    outputHandler.stderrPipe.fileHandleForWriting.write(Data("err".utf8))
                    try? outputHandler.stderrPipe.fileHandleForWriting.close()
                    outputHandler.stdoutPipe.fileHandleForWriting.write(Data("out".utf8))
                    try? outputHandler.stdoutPipe.fileHandleForWriting.close()
                    Thread.sleep(forTimeInterval: 0.3)
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = StderrExec()
            server.enableExec(withDelegate: execDelegate)

            let streams = try await client.executeCommandPair("test")

            var stdoutBuf = ByteBuffer()
            for try await chunk in streams.stdout {
                stdoutBuf.writeImmutableBuffer(chunk)
            }

            var stderrBuf = ByteBuffer()
            for try await chunk in streams.stderr {
                stderrBuf.writeImmutableBuffer(chunk)
            }

            XCTAssertEqual(String(buffer: stdoutBuf), "out")
            XCTAssertEqual(String(buffer: stderrBuf), "err")
        }
    }

    /// Stdin data written to the exec channel reaches the server process's pipe.
    /// Exercises the SSHOutboundChannelDataUnwrapper fix in ExecHandler:
    /// without it, SSHChannelData from the SSH channel can't be written to
    /// the pipe channel (which expects ByteBuffer), so stdin never arrives.
    func testExecStdinReachesServer() async throws {
        final class StdinCapture: ExecDelegate, @unchecked Sendable {
            private let lock = NSLock()
            private var _stdinReceived: Data?
            var stdinReceived: Data? {
                withStdinLock { _stdinReceived }
            }

            private func captureStdin(_ data: Data) {
                withStdinLock { _stdinReceived = data }
            }

            private func withStdinLock<Result>(_ body: () throws -> Result) rethrows -> Result {
                #if compiler(>=6.0)
                return try lock.withLock(body)
                #else
                // Swift 5.10 Foundation does not provide NSLock.withLock.
                lock.lock()
                defer { lock.unlock() }
                return try body()
                #endif
            }

            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {}
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                let input = outputHandler.stdinPipe.fileHandleForReading
                input.readabilityHandler = { [weak self] handle in
                    let data = handle.availableData
                    if !data.isEmpty {
                        self?.captureStdin(data)
                    }
                    handle.readabilityHandler = nil
                }
                DispatchQueue.global().async {
                    let output = outputHandler.stdoutPipe.fileHandleForWriting
                    output.write(Data("ack".utf8))
                    try? output.close()
                    Thread.sleep(forTimeInterval: 0.3)
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = StdinCapture()
            server.enableExec(withDelegate: execDelegate)

            try await client.withExec("echo") { inbound, outbound in
                try await outbound.write(ByteBuffer(string: "hello from stdin"))
                for try await _ in inbound {}
            }

            XCTAssertEqual(
                execDelegate.stdinReceived.flatMap { String(data: $0, encoding: .utf8) },
                "hello from stdin"
            )
        }
    }

    // MARK: - withExec-specific tests

    /// Environment variables are forwarded to the server delegate.
    func testWithExecEnvironmentVariables() async throws {
        final class Exec: ExecDelegate, @unchecked Sendable {
            struct Ctx: ExecCommandContext {
                func terminate() async throws {}
            }
            var receivedEnv: [String: String] = [:]
            func setEnvironmentValue(_ value: String, forKey key: String) async throws {
                receivedEnv[key] = value
            }
            func start(command: String, outputHandler: ExecOutputHandler) async throws -> ExecCommandContext {
                DispatchQueue.global().async {
                    try? outputHandler.stdoutPipe.fileHandleForWriting.close()
                    outputHandler.succeed(exitCode: 0)
                }
                return Ctx()
            }
        }

        try await runTest { server, client in
            let execDelegate = Exec()
            server.enableExec(withDelegate: execDelegate)

            try await client.withExec(
                "test",
                environment: [
                    .init(wantReply: true, name: "FOO", value: "bar"),
                    .init(wantReply: true, name: "BAZ", value: "qux"),
                ]
            ) { inbound, _ in
                for try await _ in inbound {}
            }

            XCTAssertEqual(execDelegate.receivedEnv["FOO"], "bar")
            XCTAssertEqual(execDelegate.receivedEnv["BAZ"], "qux")
        }
    }
}
