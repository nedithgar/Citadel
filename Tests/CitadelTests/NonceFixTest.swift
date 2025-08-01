import XCTest
import Crypto
import NIO
@testable import Citadel

final class NonceFixTest: XCTestCase {
    
    func testParseAndVerifyEd25519Certificate() throws {
        // This test can use the real certificate parsing through NIOSSH
        let (_, certificate) = try TestCertificateHelper.parseEd25519Certificate(
            certificateFile: "user_ed25519-cert.pub",
            privateKeyFile: "user_ed25519"
        )
        
        // Verify the certificate loaded successfully
        XCTAssertNotNil(certificate)
        XCTAssertEqual(certificate.type, .user)
        XCTAssertTrue(certificate.validPrincipals.contains("testuser"))
    }
}