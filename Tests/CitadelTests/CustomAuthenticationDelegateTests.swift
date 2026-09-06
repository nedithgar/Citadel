import XCTest
import NIO
import NIOSSH
@testable import Citadel

final class CustomAuthenticationDelegateTests: XCTestCase {
    private final class Offers: NIOSSHClientUserAuthenticationDelegate {
        var usernames = ["first", "second"]
        var calls = 0

        func nextAuthenticationType(availableMethods: NIOSSHAvailableUserAuthenticationMethods,
                                    nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>) {
            calls += 1
            guard !usernames.isEmpty else {
                nextChallengePromise.succeed(nil)
                return
            }
            nextChallengePromise.succeed(.init(username: usernames.removeFirst(), serviceName: "",
                offer: .password(.init(password: "test-only"))))
        }
    }

    func testCustomDelegateReceivesRepeatedChallengesAndControlsExhaustion() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { XCTAssertNoThrow(try group.syncShutdownGracefully()) }
        let delegate = Offers()
        let method = SSHAuthenticationMethod.custom(delegate)
        let first = group.next().makePromise(of: NIOSSHUserAuthenticationOffer?.self)
        method.nextAuthenticationType(availableMethods: [.password], nextChallengePromise: first)
        XCTAssertEqual(try first.futureResult.wait()?.username, "first")
        let second = group.next().makePromise(of: NIOSSHUserAuthenticationOffer?.self)
        method.nextAuthenticationType(availableMethods: [.password], nextChallengePromise: second)
        XCTAssertEqual(try second.futureResult.wait()?.username, "second")
        let exhausted = group.next().makePromise(of: NIOSSHUserAuthenticationOffer?.self)
        method.nextAuthenticationType(availableMethods: [.password], nextChallengePromise: exhausted)
        XCTAssertNil(try exhausted.futureResult.wait())
        XCTAssertEqual(delegate.calls, 3)
    }

    func testBuiltInCredentialsRemainSingleUse() throws {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        defer { XCTAssertNoThrow(try group.syncShutdownGracefully()) }
        let method = SSHAuthenticationMethod.passwordBased(username: "user", password: "test-only")
        let first = group.next().makePromise(of: NIOSSHUserAuthenticationOffer?.self)
        method.nextAuthenticationType(availableMethods: [.password], nextChallengePromise: first)
        XCTAssertEqual(try first.futureResult.wait()?.username, "user")
        let second = group.next().makePromise(of: NIOSSHUserAuthenticationOffer?.self)
        method.nextAuthenticationType(availableMethods: [.password], nextChallengePromise: second)
        XCTAssertThrowsError(try second.futureResult.wait())
    }
}
