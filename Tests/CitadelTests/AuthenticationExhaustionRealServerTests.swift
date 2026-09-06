import Foundation
import XCTest
import NIO
import NIOSSH
@testable import Citadel

/// Uses the shared SSH integration test server to reject two deliberately incorrect passwords.
final class AuthenticationExhaustionRealServerTests: XCTestCase {
    private enum ProbeError: Error { case exhausted, passwordNotSupported }

    // Accessed only on the connection's event loop, including the final snapshot.
    private final class RejectedPasswords: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
        let username: String
        let passwords = ["citadel-invalid-first-\(UUID())", "citadel-invalid-second-\(UUID())"]
        var offers = 0
        var callbacks = 0
        var advertisedMethods: [String] = []

        init(username: String) { self.username = username }

        func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods,
                                    nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
            callbacks += 1
            advertisedMethods.append(String(describing: availableMethods))
            guard availableMethods.contains(.password) else {
                nextChallengePromise.fail(ProbeError.passwordNotSupported)
                return
            }
            guard offers < passwords.count else {
                nextChallengePromise.fail(ProbeError.exhausted)
                return
            }
            let password = passwords[offers]
            offers += 1
            nextChallengePromise.succeed(.init(username: username, serviceName: "",
                offer: .password(.init(password: password))))
        }
    }

    func testAllRejectedPasswordsPropagateExhaustionBeforeTimeout() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let host = environment["SSH_HOST"],
              let portString = environment["SSH_PORT"],
              let port = Int(portString),
              let username = environment["SSH_USERNAME"],
              environment["SSH_PASSWORD"] != nil else {
            throw XCTSkip("SSH environment variables not set (SSH_HOST, SSH_PORT, SSH_USERNAME, SSH_PASSWORD)")
        }
        // Require the same configuration as the other integration tests, but send
        // deliberately incorrect passwords instead of the configured SSH_PASSWORD.
        let delegate = RejectedPasswords(username: username)
        let settings = SSHClientSettings(host: host, port: port,
            authenticationMethod: { SSHAuthenticationMethod.custom(delegate) }, hostKeyValidator: .acceptAnything())
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        addTeardownBlock { try await group.shutdownGracefully() }
        let start = ContinuousClock.now
        // Use Citadel's normal handshake pipeline while retaining the channel so a
        // failed login can also be closed and verified by test teardown.
        let channel = try await ClientBootstrap(group: group)
            .connectTimeout(.seconds(5))
            .channelInitializer { channel in
                SSHClientSession.addHandlers(on: channel,
                    inboundChannelHandler: SSHClientInboundChannelHandler(), settings: settings)
            }.connect(host: host, port: port).get()
        addTeardownBlock {
            if channel.isActive { try await channel.close().get() }
            try await channel.closeFuture.get()
            XCTAssertFalse(channel.isActive)
        }
        do {
            let handshake = try await channel.pipeline.handler(type: ClientHandshakeHandler.self).get()
            try await handshake.authenticated.get()
            XCTFail("The server unexpectedly accepted a deliberately incorrect password")
        } catch {
            guard case ProbeError.exhausted = error else {
                XCTFail("Expected explicit delegate exhaustion, received \(error)")
                return
            }
        }
        let elapsed = start.duration(to: .now)
        let snapshot = try await channel.eventLoop.submit {
            (delegate.offers, delegate.callbacks, delegate.advertisedMethods)
        }.get()
        XCTAssertEqual(snapshot.0, 2)
        XCTAssertEqual(snapshot.1, 3, "Each rejected offer must lead to another delegate callback")
        XCTAssertLessThan(elapsed, .seconds(9), "Exhaustion must propagate before Citadel's 10-second login timeout")
        print("AUTH_EXHAUSTION_PROBE offers=\(snapshot.0) callbacks=\(snapshot.1) elapsed=\(elapsed) methods=\(snapshot.2)")
    }
}
