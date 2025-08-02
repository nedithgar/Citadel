import XCTest
@testable import Citadel
import NIO
import NIOSSH
import Crypto
import _CryptoExtras

final class RealCertificateTests: XCTestCase {
    
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