import XCTest
import Crypto
import _CryptoExtras
@testable import Citadel

final class PublicKeyPEMTests: XCTestCase {
    
    func testRSAPublicKeyPEMExport() throws {
        // Generate an RSA key pair
        let keyPair = SSHKeyGenerator.generateRSA(bits: 2048)
        
        // Export public key in PEM format
        let publicKeyPEM = try keyPair.publicKeyPEMString()
        
        // Verify PEM format
        XCTAssertTrue(publicKeyPEM.hasPrefix("-----BEGIN PUBLIC KEY-----"))
        XCTAssertTrue(publicKeyPEM.hasSuffix("-----END PUBLIC KEY-----\n") || publicKeyPEM.hasSuffix("-----END PUBLIC KEY-----"))
        
        // Extract base64 content
        let lines = publicKeyPEM.components(separatedBy: .newlines)
        let base64Lines = lines.filter { !$0.contains("BEGIN") && !$0.contains("END") && !$0.isEmpty }
        let base64Content = base64Lines.joined()
        
        // Verify it's valid base64
        XCTAssertNotNil(Data(base64Encoded: base64Content))
        
        // Verify we can also export in OpenSSH format
        let openSSHFormat = try keyPair.publicKeyOpenSSHString()
        XCTAssertTrue(openSSHFormat.hasPrefix("ssh-rsa "))
    }
    
    func testEd25519PublicKeyPEMExport() throws {
        // Generate an Ed25519 key pair
        let keyPair = SSHKeyGenerator.generateEd25519()
        
        // Export public key in PEM format
        let publicKeyPEM = try keyPair.publicKeyPEMString()
        
        // Verify PEM format
        XCTAssertTrue(publicKeyPEM.hasPrefix("-----BEGIN PUBLIC KEY-----"))
        XCTAssertTrue(publicKeyPEM.hasSuffix("-----END PUBLIC KEY-----\n") || publicKeyPEM.hasSuffix("-----END PUBLIC KEY-----"))
        
        // Extract base64 content
        let lines = publicKeyPEM.components(separatedBy: .newlines)
        let base64Lines = lines.filter { !$0.contains("BEGIN") && !$0.contains("END") && !$0.isEmpty }
        let base64Content = base64Lines.joined()
        
        // Verify it's valid base64
        let derData = Data(base64Encoded: base64Content)
        XCTAssertNotNil(derData)
        
        // Ed25519 public key in SPKI format should be 44 bytes
        // (12 bytes header + 32 bytes key)
        XCTAssertEqual(derData?.count, 44)
        
        // Verify we can also export in OpenSSH format
        let openSSHFormat = try keyPair.publicKeyOpenSSHString()
        XCTAssertTrue(openSSHFormat.hasPrefix("ssh-ed25519 "))
    }
    
    func testECDSAP256PublicKeyPEMExport() throws {
        // Generate a P256 key pair
        let keyPair = SSHKeyGenerator.generateECDSA(curve: .p256)
        
        // Export public key in PEM format
        let publicKeyPEM = try keyPair.publicKeyPEMString()
        
        // Verify PEM format
        XCTAssertTrue(publicKeyPEM.hasPrefix("-----BEGIN PUBLIC KEY-----"))
        XCTAssertTrue(publicKeyPEM.hasSuffix("-----END PUBLIC KEY-----\n") || publicKeyPEM.hasSuffix("-----END PUBLIC KEY-----"))
        
        // Verify we can also export in OpenSSH format
        let openSSHFormat = try keyPair.publicKeyOpenSSHString()
        XCTAssertTrue(openSSHFormat.hasPrefix("ecdsa-sha2-nistp256 "))
    }
    
    func testECDSAP384PublicKeyPEMExport() throws {
        // Generate a P384 key pair
        let keyPair = SSHKeyGenerator.generateECDSA(curve: .p384)
        
        // Export public key in PEM format
        let publicKeyPEM = try keyPair.publicKeyPEMString()
        
        // Verify PEM format
        XCTAssertTrue(publicKeyPEM.hasPrefix("-----BEGIN PUBLIC KEY-----"))
        XCTAssertTrue(publicKeyPEM.hasSuffix("-----END PUBLIC KEY-----\n") || publicKeyPEM.hasSuffix("-----END PUBLIC KEY-----"))
        
        // Verify we can also export in OpenSSH format
        let openSSHFormat = try keyPair.publicKeyOpenSSHString()
        XCTAssertTrue(openSSHFormat.hasPrefix("ecdsa-sha2-nistp384 "))
    }
    
    func testECDSAP521PublicKeyPEMExport() throws {
        // Generate a P521 key pair
        let keyPair = SSHKeyGenerator.generateECDSA(curve: .p521)
        
        // Export public key in PEM format
        let publicKeyPEM = try keyPair.publicKeyPEMString()
        
        // Verify PEM format
        XCTAssertTrue(publicKeyPEM.hasPrefix("-----BEGIN PUBLIC KEY-----"))
        XCTAssertTrue(publicKeyPEM.hasSuffix("-----END PUBLIC KEY-----\n") || publicKeyPEM.hasSuffix("-----END PUBLIC KEY-----"))
        
        // Verify we can also export in OpenSSH format
        let openSSHFormat = try keyPair.publicKeyOpenSSHString()
        XCTAssertTrue(openSSHFormat.hasPrefix("ecdsa-sha2-nistp521 "))
    }
    
    func testPublicKeyPEMLineFormatting() throws {
        // Generate an RSA key pair (tends to have longer keys)
        let keyPair = SSHKeyGenerator.generateRSA(bits: 4096)
        
        // Export public key in PEM format
        let publicKeyPEM = try keyPair.publicKeyPEMString()
        
        // Verify line formatting
        let lines = publicKeyPEM.components(separatedBy: .newlines)
        
        // Check header and footer
        XCTAssertEqual(lines.first, "-----BEGIN PUBLIC KEY-----")
        XCTAssertTrue(lines.last == "-----END PUBLIC KEY-----" || lines.dropLast().last == "-----END PUBLIC KEY-----")
        
        // Check base64 lines are properly formatted (64 chars max)
        let base64Lines = lines.filter { !$0.contains("BEGIN") && !$0.contains("END") && !$0.isEmpty }
        for line in base64Lines.dropLast() {
            XCTAssertLessThanOrEqual(line.count, 64)
        }
    }
}