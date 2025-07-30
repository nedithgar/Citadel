import XCTest
import Crypto
@testable import Citadel

final class Ed25519PEMTests: XCTestCase {
    
    // MARK: - Private Key Tests
    
    func testPrivateKeyPEMRoundTrip() throws {
        // Generate a new Ed25519 private key
        let originalKey = Curve25519.Signing.PrivateKey()
        
        // Export to PEM
        let pemString = originalKey.pemRepresentation
        
        // Verify PEM format
        XCTAssertTrue(pemString.hasPrefix("-----BEGIN PRIVATE KEY-----"))
        XCTAssertTrue(pemString.contains("-----END PRIVATE KEY-----"))
        
        // Import from PEM
        let importedKey = try Curve25519.Signing.PrivateKey(pemRepresentation: pemString)
        
        // Verify the keys are equivalent by comparing raw representations
        XCTAssertEqual(originalKey.rawRepresentation, importedKey.rawRepresentation)
        
        // Test that signatures work correctly
        let message = "Test message".data(using: .utf8)!
        let signature1 = try originalKey.signature(for: message)
        let signature2 = try importedKey.signature(for: message)
        
        // Both keys should produce valid signatures
        XCTAssertTrue(originalKey.publicKey.isValidSignature(signature1, for: message))
        XCTAssertTrue(originalKey.publicKey.isValidSignature(signature2, for: message))
        XCTAssertTrue(importedKey.publicKey.isValidSignature(signature1, for: message))
        XCTAssertTrue(importedKey.publicKey.isValidSignature(signature2, for: message))
    }
    
    func testPrivateKeyDERRoundTrip() throws {
        // Generate a new Ed25519 private key
        let originalKey = Curve25519.Signing.PrivateKey()
        
        // Export to DER
        let derData = originalKey.pkcs8DERRepresentation
        
        // Verify DER has reasonable size (should be around 48 bytes for Ed25519)
        XCTAssertGreaterThan(derData.count, 40)
        XCTAssertLessThan(derData.count, 60)
        
        // Import from DER
        let importedKey = try Curve25519.Signing.PrivateKey(pkcs8DERRepresentation: derData)
        
        // Verify the keys are equivalent
        XCTAssertEqual(originalKey.rawRepresentation, importedKey.rawRepresentation)
    }
    
    // MARK: - Public Key Tests
    
    func testPublicKeyPEMRoundTrip() throws {
        // Generate a new Ed25519 key pair
        let privateKey = Curve25519.Signing.PrivateKey()
        let originalPublicKey = privateKey.publicKey
        
        // Export to PEM
        let pemString = originalPublicKey.pemRepresentation
        
        // Verify PEM format
        XCTAssertTrue(pemString.hasPrefix("-----BEGIN PUBLIC KEY-----"))
        XCTAssertTrue(pemString.contains("-----END PUBLIC KEY-----"))
        
        // Import from PEM
        let importedKey = try Curve25519.Signing.PublicKey(pemRepresentation: pemString)
        
        // Verify the keys are equivalent
        XCTAssertEqual(originalPublicKey.rawRepresentation, importedKey.rawRepresentation)
        
        // Verify signature validation works
        let message = "Test message".data(using: .utf8)!
        let signature = try privateKey.signature(for: message)
        
        XCTAssertTrue(originalPublicKey.isValidSignature(signature, for: message))
        XCTAssertTrue(importedKey.isValidSignature(signature, for: message))
    }
    
    func testPublicKeyDERRoundTrip() throws {
        // Generate a new Ed25519 public key
        let privateKey = Curve25519.Signing.PrivateKey()
        let originalPublicKey = privateKey.publicKey
        
        // Export to DER
        let derData = originalPublicKey.spkiDERRepresentation
        
        // Verify DER has reasonable size
        XCTAssertGreaterThan(derData.count, 40)
        XCTAssertLessThan(derData.count, 50)
        
        // Import from DER
        let importedKey = try Curve25519.Signing.PublicKey(spkiDERRepresentation: derData)
        
        // Verify the keys are equivalent
        XCTAssertEqual(originalPublicKey.rawRepresentation, importedKey.rawRepresentation)
    }
    
    // MARK: - SSHKeyGenerator Integration Tests
    
    func testSSHKeyGeneratorPEMExport() throws {
        // Generate Ed25519 key using SSHKeyGenerator
        let keyPair = SSHKeyGenerator.generateEd25519()
        
        // Export to PEM (should no longer return nil)
        let pemString = try XCTUnwrap(keyPair.privateKeyPEMString())
        
        // Verify it's valid PEM
        XCTAssertTrue(pemString.hasPrefix("-----BEGIN PRIVATE KEY-----"))
        XCTAssertTrue(pemString.contains("-----END PRIVATE KEY-----"))
        
        // Import and verify
        let importedKey = try Curve25519.Signing.PrivateKey(pemRepresentation: pemString)
        
        // Generate SSH representation from both keys
        let originalSSH = try keyPair.privateKeyOpenSSHString()
        let importedKeyPair = SSHKeyPair(ed25519Key: importedKey, keyType: .ed25519)
        let importedSSH = try importedKeyPair.privateKeyOpenSSHString()
        
        // Both should produce valid SSH keys (they might differ in metadata but should work)
        XCTAssertTrue(originalSSH.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----"))
        XCTAssertTrue(importedSSH.hasPrefix("-----BEGIN OPENSSH PRIVATE KEY-----"))
    }
    
    // MARK: - Error Handling Tests
    
    func testInvalidPrivateKeyPEM() throws {
        let invalidPEMs = [
            // Empty
            "",
            // Missing headers
            "SGVsbG8gV29ybGQ=",
            // Wrong header
            "-----BEGIN RSA PRIVATE KEY-----\nSGVsbG8gV29ybGQ=\n-----END RSA PRIVATE KEY-----",
            // Invalid base64
            "-----BEGIN PRIVATE KEY-----\nInvalid!@#$%\n-----END PRIVATE KEY-----",
            // Valid base64 but invalid DER structure
            "-----BEGIN PRIVATE KEY-----\nSGVsbG8gV29ybGQ=\n-----END PRIVATE KEY-----"
        ]
        
        for pem in invalidPEMs {
            XCTAssertThrowsError(try Curve25519.Signing.PrivateKey(pemRepresentation: pem))
        }
    }
    
    func testInvalidPublicKeyPEM() throws {
        let invalidPEMs = [
            // Empty
            "",
            // Missing headers
            "SGVsbG8gV29ybGQ=",
            // Wrong header
            "-----BEGIN RSA PUBLIC KEY-----\nSGVsbG8gV29ybGQ=\n-----END RSA PUBLIC KEY-----",
            // Invalid base64
            "-----BEGIN PUBLIC KEY-----\nInvalid!@#$%\n-----END PUBLIC KEY-----",
            // Valid base64 but invalid DER structure
            "-----BEGIN PUBLIC KEY-----\nSGVsbG8gV29ybGQ=\n-----END PUBLIC KEY-----"
        ]
        
        for pem in invalidPEMs {
            XCTAssertThrowsError(try Curve25519.Signing.PublicKey(pemRepresentation: pem))
        }
    }
    
    func testInvalidDERData() throws {
        let invalidDERs: [Data] = [
            // Empty
            Data(),
            // Too short
            Data([0x30, 0x05]),
            // Invalid structure
            Data([0x02, 0x01, 0x00]),
            // Wrong algorithm OID
            Data([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71])
        ]
        
        for der in invalidDERs {
            XCTAssertThrowsError(try Curve25519.Signing.PrivateKey(pkcs8DERRepresentation: der))
            XCTAssertThrowsError(try Curve25519.Signing.PublicKey(spkiDERRepresentation: der))
        }
    }
    
    // MARK: - Interoperability Tests
    
    func testOpenSSLGeneratedPrivateKey() throws {
        // This is a test Ed25519 private key generated with:
        // openssl genpkey -algorithm ed25519
        let openSSLPrivateKeyPEM = """
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIJC5302p7lNKfQwvJIUEN5+z8dHqVBiWXLFDVqpGWitD
        -----END PRIVATE KEY-----
        """
        
        // Should be able to import it
        let privateKey = try Curve25519.Signing.PrivateKey(pemRepresentation: openSSLPrivateKeyPEM)
        
        // Verify it can be used for signing
        let message = "Test message".data(using: .utf8)!
        let signature = try privateKey.signature(for: message)
        XCTAssertTrue(privateKey.publicKey.isValidSignature(signature, for: message))
        
        // Export and reimport to verify round-trip
        let exportedPEM = privateKey.pemRepresentation
        let reimported = try Curve25519.Signing.PrivateKey(pemRepresentation: exportedPEM)
        XCTAssertEqual(privateKey.rawRepresentation, reimported.rawRepresentation)
    }
    
    func testOpenSSLGeneratedPublicKey() throws {
        // This is the public key corresponding to the private key above
        // Generated with: openssl pkey -in private.pem -pubout
        let openSSLPublicKeyPEM = """
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEA3oPb2OlPRNNZfX8k4Yy9A7REE1N9ca8nKAyNlCCxDnI=
        -----END PUBLIC KEY-----
        """
        
        // Should be able to import it
        let publicKey = try Curve25519.Signing.PublicKey(pemRepresentation: openSSLPublicKeyPEM)
        
        // Verify the raw representation has the expected length
        XCTAssertEqual(publicKey.rawRepresentation.count, 32)
        
        // Export and reimport to verify round-trip
        let exportedPEM = publicKey.pemRepresentation
        let reimported = try Curve25519.Signing.PublicKey(pemRepresentation: exportedPEM)
        XCTAssertEqual(publicKey.rawRepresentation, reimported.rawRepresentation)
    }
}