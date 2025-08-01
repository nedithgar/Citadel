import XCTest
@testable import Citadel
import Crypto
import _CryptoExtras
import Foundation
import NIO
import NIOSSH

final class CertificateAuthenticationTests: XCTestCase {
    
    // Test that certificate types are properly registered and can be used
    func testCertificateTypesAreRegistered() throws {
        // SKIP TEST: This test uses the old custom certificate implementation that has been removed
        // The functionality is now provided by NIOSSH's native certificate support
        // See CertificateAuthenticationMethodRealTests.swift for the updated tests
        throw XCTSkip("Test uses deprecated certificate types - functionality moved to NIOSSH")
    }
    
    // Test that certificate authentication can be created with Ed25519
    func testEd25519CertificateAuthentication() throws {
        throw XCTSkip("Test uses deprecated certificate types - see CertificateAuthenticationMethodRealTests.swift")
    }
    
    // Test that certificate authentication can be created with RSA
    func testRSACertificateAuthentication() throws {
        throw XCTSkip("Test uses deprecated certificate types - see CertificateAuthenticationMethodRealTests.swift")
    }
    
    // Test that certificate authentication can be created with P256
    func testP256CertificateAuthentication() throws {
        throw XCTSkip("Test uses deprecated certificate types - see CertificateAuthenticationMethodRealTests.swift")
    }
    
    // Test that certificate authentication can be created with P384
    func testP384CertificateAuthentication() throws {
        throw XCTSkip("Test uses deprecated certificate types - see CertificateAuthenticationMethodRealTests.swift")
    }
    
    // Test that certificate authentication can be created with P521
    func testP521CertificateAuthentication() throws {
        throw XCTSkip("Test uses deprecated certificate types - see CertificateAuthenticationMethodRealTests.swift")
    }
}