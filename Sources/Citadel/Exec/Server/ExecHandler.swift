//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import NIOCore
import NIOFoundationCompat
import NIOPosix
import NIOSSH

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Bionic)
import Bionic
#endif

private func closeFileDescriptor(_ descriptor: CInt) {
    #if canImport(Darwin)
    _ = Darwin.close(descriptor)
    #elseif canImport(Glibc)
    _ = Glibc.close(descriptor)
    #elseif canImport(Musl)
    _ = Musl.close(descriptor)
    #elseif canImport(Bionic)
    _ = Bionic.close(descriptor)
    #endif
}

private func duplicateFileDescriptor(_ descriptor: CInt) throws -> CInt {
    let duplicatedDescriptor = dup(descriptor)
    guard duplicatedDescriptor >= 0 else {
        throw IOError(errnoCode: errno, reason: "dup")
    }
    return duplicatedDescriptor
}

enum SSHServerError: Error {
    case invalidCommand
    case invalidDataType
    case invalidChannelType
    case alreadyListening
    case notListening
}

/// Streams a process's stderr pipe into the SSH channel and completes only after
/// every forwarded write has flushed. Both channels use the same event loop, so
/// the mutable write chain and completion state remain event-loop isolated.
private final class ExecStderrHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private let outputChannel: Channel
    private let completionPromise: EventLoopPromise<Void>
    private var pendingWrites: EventLoopFuture<Void>
    private var isComplete = false

    init(outputChannel: Channel, completionPromise: EventLoopPromise<Void>) {
        self.outputChannel = outputChannel
        self.completionPromise = completionPromise
        self.pendingWrites = outputChannel.eventLoop.makeSucceededVoidFuture()
    }

    func channelActive(context: ChannelHandlerContext) {
        context.fireChannelActive()
        context.read()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buffer = self.unwrapInboundIn(data)
        let write = outputChannel.writeAndFlush(
            SSHChannelData(type: .stdErr, data: .byteBuffer(buffer))
        )
        pendingWrites = pendingWrites.and(write).map { _ in }
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        context.fireChannelReadComplete()
        pendingWrites.whenComplete { result in
            guard !self.isComplete else { return }
            switch result {
            case .success:
                // Keep at most one bounded pipe read batch queued behind the SSH
                // channel's remote-window flow control.
                context.read()
            case .failure(let error):
                self.failAndClose(error, context: context)
            }
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        completeAfterPendingWrites()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        failAndClose(error, context: context)
    }

    private func failAndClose(_ error: Error, context: ChannelHandlerContext) {
        fail(error)
        outputChannel.close(promise: nil)
        context.close(promise: nil)
    }

    private func completeAfterPendingWrites() {
        guard !isComplete else { return }
        isComplete = true
        completionPromise.completeWith(pendingWrites)
    }

    private func fail(_ error: Error) {
        guard !isComplete else { return }
        isComplete = true
        completionPromise.fail(error)
    }
}

final class ExecHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = SSHChannelData
    typealias OutboundIn = SSHChannelData
    typealias OutboundOut = SSHChannelData
    
    let delegate: ExecDelegate?
    
    init(delegate: ExecDelegate?, username: String?) {
        self.delegate = delegate
        self.username = username
    }
    
    var context: ExecCommandContext?
    var pipeChannel: Channel?
    var stderrPipeChannel: Channel?
    var environment: [String: String] = [:]
    let username: String?
    
    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            context.fireErrorCaught(error)
        }
    }
    
    func channelInactive(context: ChannelHandlerContext) {
        self.pipeChannel?.close(promise: nil)
        self.stderrPipeChannel?.close(promise: nil)
        Task {
            try await self.context?.terminate()
            self.context = nil
            self.pipeChannel = nil
            self.stderrPipeChannel = nil
        }
        context.fireChannelInactive()
    }
    
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let event as SSHChannelRequestEvent.ExecRequest:
            if let delegate = delegate {
                self.exec(event, delegate: delegate, channel: context.channel)
            } else if event.wantReply {
                context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                    context.channel.close(promise: nil)
                }
            }
        case let event as SSHChannelRequestEvent.EnvironmentRequest:
            if let delegate = delegate {
                Task {
                    try await delegate.setEnvironmentValue(event.value, forKey: event.name)
                }
            }
        case ChannelEvent.inputClosed:
            Task {
                try await self.context?.inputClosed()
            }
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(data)
    }
    
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        context.write(data, promise: promise)
    }
    
    private func exec(_ event: SSHChannelRequestEvent.ExecRequest, delegate: ExecDelegate, channel: Channel) {
        let successPromise = channel.eventLoop.makePromise(of: Int.self)
        let stderrCompletionPromise = channel.eventLoop.makePromise(of: Void.self)
        let handler = ExecOutputHandler(username: username) { code in
            successPromise.succeed(code)
        } onFailure: { _ in
            // An arbitrary process error has no SSH wire representation. Use
            // OpenSSH's conventional abnormal-session status instead.
            successPromise.succeed(255)
        }
        
        let (ours, theirs) = GlueHandler.matchedPair()

        // Tracks whether SSH_MSG_CHANNEL_SUCCESS has been sent for this exec request.
        // Once sent, a later failure in the pipeline must NOT send SSH_MSG_CHANNEL_FAILURE
        // (that would be a protocol violation that confuses the client into throwing
        // channelFailure instead of receiving a clean EOF). All accesses occur on the
        // channel's event loop so no locking is needed.
        var channelSuccessSent = false
        
        channel.pipeline.addHandler(ours).flatMap { _ -> EventLoopFuture<Channel> in
            let stdoutDescriptor: CInt
            do {
                stdoutDescriptor = try duplicateFileDescriptor(
                    handler.stdoutPipe.fileHandleForReading.fileDescriptor
                )
            } catch {
                let failure: EventLoopFuture<Channel> = channel.eventLoop.makeFailedFuture(error)
                return failure
            }

            let stdinDescriptor: CInt
            do {
                stdinDescriptor = try duplicateFileDescriptor(
                    handler.stdinPipe.fileHandleForWriting.fileDescriptor
                )
            } catch {
                closeFileDescriptor(stdoutDescriptor)
                let failure: EventLoopFuture<Channel> = channel.eventLoop.makeFailedFuture(error)
                return failure
            }

            return NIOPipeBootstrap(group: channel.eventLoop)
                .channelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
                .channelInitializer { pipeChannel in
                    pipeChannel.pipeline.addHandlers(SSHInboundChannelDataWrapper(), SSHOutboundChannelDataUnwrapper(), theirs)
                }.takingOwnershipOfDescriptors(
                    input: stdoutDescriptor,
                    output: stdinDescriptor
                )
                .flatMapErrorThrowing { error in
                    // A failed bootstrap leaves ownership with the caller.
                    closeFileDescriptor(stdoutDescriptor)
                    closeFileDescriptor(stdinDescriptor)
                    throw error
                }
        }.flatMap { pipeChannel -> EventLoopFuture<(Channel, Channel)> in
            // An input-only NIO channel streams stderr without blocking a global
            // worker. Its handler fulfills stderrCompletionPromise only after EOF
            // and after every SSH stderr write has flushed.
            let stderrDescriptor: CInt
            do {
                stderrDescriptor = try duplicateFileDescriptor(
                    handler.stderrPipe.fileHandleForReading.fileDescriptor
                )
            } catch {
                return pipeChannel.close(mode: .all)
                    .flatMapError { _ in pipeChannel.eventLoop.makeSucceededVoidFuture() }
                    .flatMap { pipeChannel.eventLoop.makeFailedFuture(error) }
            }

            return NIOPipeBootstrap(group: channel.eventLoop)
                .channelOption(ChannelOptions.autoRead, value: false)
                .channelInitializer { stderrChannel in
                    stderrChannel.pipeline.addHandler(
                        ExecStderrHandler(
                            outputChannel: channel,
                            completionPromise: stderrCompletionPromise
                        )
                    )
                }.takingOwnershipOfDescriptor(
                    input: stderrDescriptor
                )
                .map { stderrPipeChannel in
                    (pipeChannel, stderrPipeChannel)
                }
                .flatMapError { error in
                    // A failed bootstrap leaves ownership with the caller. Also
                    // tear down the standard-I/O channel created just above.
                    closeFileDescriptor(stderrDescriptor)
                    return pipeChannel.close(mode: .all)
                        .flatMapError { _ in pipeChannel.eventLoop.makeSucceededVoidFuture() }
                        .flatMap { pipeChannel.eventLoop.makeFailedFuture(error) }
                }
        }.flatMap { channels -> EventLoopFuture<Channel> in
            let (pipeChannel, stderrPipeChannel) = channels
            self.pipeChannel = pipeChannel
            self.stderrPipeChannel = stderrPipeChannel
            let start = channel.eventLoop.makePromise(of: Void.self)
            start.completeWithTask {
                do {
                    self.context = try await delegate.start(
                        command: event.command,
                        outputHandler: handler
                    )
                } catch {
                    try await pipeChannel.close(mode: .all)
                }
            }
            
            return start.futureResult.flatMap {
                if event.wantReply {
                    return channel.triggerUserOutboundEvent(ChannelSuccessEvent()).map {
                        channelSuccessSent = true
                        return pipeChannel
                    }
                } else {
                    return channel.eventLoop.makeSucceededFuture(pipeChannel)
                }
            }
        }.flatMap { pipeChannel in
            successPromise.futureResult.flatMap { code in
                // A delegate may retain the output handler after signaling completion.
                // Close its writer so only any duplicated process writer controls EOF.
                try? handler.stderrPipe.fileHandleForWriting.close()
                // On Linux, NIOPipeBootstrap may close the pipeChannel itself when the
                // stdout pipe's write end is closed while data is in-flight (EPOLLHUP).
                // By the time succeed() is called the pipe has been fully drained, so
                // ignoring an already-closed error here is safe.
                return pipeChannel.close(mode: .all)
                    .flatMapErrorThrowing { error in
                        guard let channelError = error as? ChannelError,
                              channelError == .alreadyClosed else {
                            throw error
                        }
                    }
                    .and(stderrCompletionPromise.futureResult)
                    .map { _ in code }
            }
        }.flatMap { code in
            channel.triggerUserOutboundEvent(SSHChannelRequestEvent.ExitStatus(exitStatus: code))
        }.whenComplete { result in
            switch result {
            case .success:
                channel.close(promise: nil)
            case .failure:
                // Only send ChannelFailureEvent when the exec setup itself failed (before
                // ChannelSuccessEvent was sent). Sending it after ChannelSuccessEvent is a
                // protocol violation and causes the client to throw channelFailure instead
                // of receiving a clean stream termination.
                if event.wantReply && !channelSuccessSent {
                    channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                        channel.close(promise: nil)
                    }
                } else {
                    channel.close(promise: nil)
                }
            }
        }
    }
}
