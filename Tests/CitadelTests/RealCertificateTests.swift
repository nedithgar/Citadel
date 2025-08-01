import XCTest
@testable import Citadel
import NIO
import NIOSSH
import Crypto
import _CryptoExtras

final class RealCertificateTests: XCTestCase {
    
    // MARK: - Ed25519 Certificate Tests
    
    func testParseEd25519Certificate() throws {
        // SKIP TEST: This test uses the old custom certificate parsing that has been removed
        // Certificate parsing is now handled by NIOSSH's native support
        // See CertificateAuthenticationMethodRealTests.swift for updated tests
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testParseRSACertificate() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testParseECDSAP256Certificate() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testParseCertificateWithTimeConstraints() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testParseCertificateWithLimitedPrincipals() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testParseCertificateWithCriticalOptions() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testParseCertificateWithAllExtensions() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testParseCertificateWithNoExtensions() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testParseHostCertificate() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testMultipleCertificatesInSingleFile() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testVerifyEd25519CertificateSignature() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testVerifyRSACertificateSignature() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testVerifyECDSAP256CertificateSignature() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testInvalidSignatureShouldFail() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testParseECDSAP384Certificate() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testParseECDSAP521Certificate() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testVerifyECDSAP384CertificateSignature() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    func testVerifyECDSAP521CertificateSignature() throws {
        throw XCTSkip("Test uses deprecated certificate parsing - functionality moved to NIOSSH")
    }
    
    // This test can still work as it uses the helper which now returns NIOSSHCertifiedPublicKey
    func testCertificateAuthentication() throws {
        // Load the certificate and key using the updated helper
        let (privateKey, certificate) = try TestCertificateHelper.parseEd25519Certificate(
            certificateFile: "user_ed25519-cert.pub",
            privateKeyFile: "user_ed25519"
        )
        
        // Create authentication method
        let authMethod = try SSHAuthenticationMethod.ed25519Certificate(
            username: "testuser",
            privateKey: privateKey,
            certificate: certificate
        )
        
        XCTAssertNotNil(authMethod)
    }
}