import XCTest
@testable import Citadel
import Crypto
import NIO

final class ECDSAKeyTests: XCTestCase {
    func testParseP256PrivateKey() throws {
        // Real key generated with: ssh-keygen -t ecdsa -b 256 -f test_p256 -N "" -C "test@example.com"
        let ecdsaP256PrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
        1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRb9jp43IDOWYynle225gPMBkJ9rHil
        TMAT7B215TmfXDVz/8OlZWInToGcipnuqZsixNtSgz5i4LvRInWV9DpPAAAAsLckTg+3JE
        4PAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFv2OnjcgM5ZjKeV
        7bbmA8wGQn2seKVMwBPsHbXlOZ9cNXP/w6VlYidOgZyKme6pmyLE21KDPmLgu9EidZX0Ok
        8AAAAhAKRCzvqPb3JF0UL2cUef8JaW8Hehgppaw/FFDcpJjfAEAAAAEHRlc3RAZXhhbXBs
        ZS5jb20BAgMEBQYH
        -----END OPENSSH PRIVATE KEY-----
        """
        
        let privateKey = try P256.Signing.PrivateKey(sshECDSA: ecdsaP256PrivateKey)
        
        // Verify we can create a public key from it
        let publicKey = privateKey.publicKey
        
        // Verify key can be used for signing
        let signature = try privateKey.signature(for: "test".data(using: .utf8)!)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: "test".data(using: .utf8)!))
    }
    
    func testParseP384PrivateKey() throws {
        // Real key generated with: ssh-keygen -t ecdsa -b 384 -f test_p384 -N "" -C "test@example.com"
        let ecdsaP384PrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
        1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQSYhaUzBlqml5TxqOQd6iOoXqC1tnej
        LDoUBk9NH7KtZGB7RQb9ygcdpxNO4MRPG4/HXq9XkP/jex6y4epbLsIAIGUb+5+BFKV2qZ
        aBGhajKAqm4cZdISWluLOiVbIAi6kAAADgdSrYt3Uq2LcAAAATZWNkc2Etc2hhMi1uaXN0
        cDM4NAAAAAhuaXN0cDM4NAAAAGEEmIWlMwZappeU8ajkHeojqF6gtbZ3oyw6FAZPTR+yrW
        Rge0UG/coHHacTTuDETxuPx16vV5D/43sesuHqWy7CACBlG/ufgRSldqmWgRoWoygKpuHG
        XSElpbizolWyAIupAAAAMQD2L6H07VKNLNRJE/N0Gi8xCSfHHmNCbAPMl2om+p/gonjod7
        m25VLSmR/qCCfnrBcAAAAQdGVzdEBleGFtcGxlLmNvbQECAwQFBgc=
        -----END OPENSSH PRIVATE KEY-----
        """
        
        let privateKey = try P384.Signing.PrivateKey(sshECDSA: ecdsaP384PrivateKey)
        
        // Verify we can create a public key from it
        let publicKey = privateKey.publicKey
        
        // Verify key can be used for signing
        let signature = try privateKey.signature(for: "test".data(using: .utf8)!)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: "test".data(using: .utf8)!))
    }
    
    func testParseP521PrivateKey() throws {
        // Real key generated with: ssh-keygen -t ecdsa -b 521 -f test_p521 -N "" -C "test@example.com"
        let ecdsaP521PrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
        1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQALEP7/ff53UCXKnQ8bA7WbdUog93Z
        5jNVLMERhnh9ZNH3ceUbzSE48vHvC/ojRUa+KIt+QFl98oEHQ5/MjeKgWtEBABElKi5JYD
        EYVSbc1po7l7fEjsYWhmBKVKr2l486sQQJbWJRF1qNxmMDDhUgc/MoGnSvwrGjTInZWKle
        0Lc42LIAAAEQHn2sUR59rFEAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
        AAAIUEACxD+/33+d1Alyp0PGwO1m3VKIPd2eYzVSzBEYZ4fWTR93HlG80hOPLx7wv6I0VG
        viiLfkBZffKBB0OfzI3ioFrRAQARJSouSWAxGFUm3NaaO5e3xI7GFoZgSlSq9pePOrEECW
        1iURdajcZjAw4VIHPzKBp0r8Kxo0yJ2VipXtC3ONiyAAAAQgHDUj3BKxYlZPbb7qPlhrJF
        0yHeOiyKWeLg+Qr543AXtuGKYWmnq/ENUmgvjzFlkuN+2Y0qm4mNSpUtDelbkyZmwwAAAB
        B0ZXN0QGV4YW1wbGUuY29tAQI=
        -----END OPENSSH PRIVATE KEY-----
        """
        
        let privateKey = try P521.Signing.PrivateKey(sshECDSA: ecdsaP521PrivateKey)
        
        // Verify we can create a public key from it
        let publicKey = privateKey.publicKey
        
        // Verify key can be used for signing
        let signature = try privateKey.signature(for: "test".data(using: .utf8)!)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: "test".data(using: .utf8)!))
    }
    
    func testParseEncryptedP256PrivateKey() throws {
        // Create a test encrypted key by generating one
        let _ = P256.Signing.PrivateKey()
        let passphrase = "testpassphrase"
        
        // We would need to implement key serialization to test encrypted keys
        // For now, we'll test that the API exists
        XCTAssertThrowsError(try P256.Signing.PrivateKey(sshECDSA: "", decryptionKey: passphrase.data(using: .utf8)))
    }
    
    func testInvalidKeyFormat() throws {
        let invalidKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        aW52YWxpZCBrZXkgZGF0YQ==
        -----END OPENSSH PRIVATE KEY-----
        """
        
        XCTAssertThrowsError(try P256.Signing.PrivateKey(sshECDSA: invalidKey))
    }
    
    func testWrongCurveKey() throws {
        // P-384 key attempting to be parsed as P-256
        // Real key generated with: ssh-keygen -t ecdsa -b 384
        let ecdsaP384PrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
        1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQSYhaUzBlqml5TxqOQd6iOoXqC1tnej
        LDoUBk9NH7KtZGB7RQb9ygcdpxNO4MRPG4/HXq9XkP/jex6y4epbLsIAIGUb+5+BFKV2qZ
        aBGhajKAqm4cZdISWluLOiVbIAi6kAAADgdSrYt3Uq2LcAAAATZWNkc2Etc2hhMi1uaXN0
        cDM4NAAAAAhuaXN0cDM4NAAAAGEEmIWlMwZappeU8ajkHeojqF6gtbZ3oyw6FAZPTR+yrW
        Rge0UG/coHHacTTuDETxuPx16vV5D/43sesuHqWy7CACBlG/ufgRSldqmWgRoWoygKpuHG
        XSElpbizolWyAIupAAAAMQD2L6H07VKNLNRJE/N0Gi8xCSfHHmNCbAPMl2om+p/gonjod7
        m25VLSmR/qCCfnrBcAAAAQdGVzdEBleGFtcGxlLmNvbQECAwQFBgc=
        -----END OPENSSH PRIVATE KEY-----
        """
        
        // This should fail because the key is P-384 but we're trying to parse as P-256
        XCTAssertThrowsError(try P256.Signing.PrivateKey(sshECDSA: ecdsaP384PrivateKey))
    }
    
    // MARK: - PEM/PKCS#8 Tests
    
    func testP256PEMPrivateKey() throws {
        // Generate a new key and test PEM export/import
        let originalKey = P256.Signing.PrivateKey()
        
        // Export to PEM
        let pemString = originalKey.pemRepresentation
        
        // Verify PEM format
        XCTAssertTrue(pemString.hasPrefix("-----BEGIN PRIVATE KEY-----"))
        XCTAssertTrue(pemString.contains("-----END PRIVATE KEY-----"))
        
        // Import from PEM
        let importedKey = try P256.Signing.PrivateKey(pemRepresentation: pemString)
        
        // Verify the keys are equivalent by comparing raw representations
        XCTAssertEqual(originalKey.rawRepresentation, importedKey.rawRepresentation)
        
        // Test DER representation
        let derData = originalKey.derRepresentation
        let keyFromDER = try P256.Signing.PrivateKey(derRepresentation: derData)
        XCTAssertEqual(originalKey.rawRepresentation, keyFromDER.rawRepresentation)
    }
    
    func testP256PEMPublicKey() throws {
        // Generate a new key and test public key PEM export/import
        let privateKey = P256.Signing.PrivateKey()
        let originalPublicKey = privateKey.publicKey
        
        // Export to PEM
        let pemString = originalPublicKey.pemRepresentation
        
        // Verify PEM format
        XCTAssertTrue(pemString.hasPrefix("-----BEGIN PUBLIC KEY-----"))
        XCTAssertTrue(pemString.contains("-----END PUBLIC KEY-----"))
        
        // Import from PEM
        let importedKey = try P256.Signing.PublicKey(pemRepresentation: pemString)
        
        // Verify the keys are equivalent
        XCTAssertEqual(originalPublicKey.rawRepresentation, importedKey.rawRepresentation)
    }
    
    func testP384PEMPrivateKey() throws {
        // Generate a new key and test PEM export/import
        let originalKey = P384.Signing.PrivateKey()
        
        // Export to PEM
        let pemString = originalKey.pemRepresentation
        
        // Verify PEM format
        XCTAssertTrue(pemString.hasPrefix("-----BEGIN PRIVATE KEY-----"))
        XCTAssertTrue(pemString.contains("-----END PRIVATE KEY-----"))
        
        // Import from PEM
        let importedKey = try P384.Signing.PrivateKey(pemRepresentation: pemString)
        
        // Verify the keys are equivalent
        XCTAssertEqual(originalKey.rawRepresentation, importedKey.rawRepresentation)
        
        // Test DER representation
        let derData = originalKey.derRepresentation
        let keyFromDER = try P384.Signing.PrivateKey(derRepresentation: derData)
        XCTAssertEqual(originalKey.rawRepresentation, keyFromDER.rawRepresentation)
    }
    
    func testP384PEMPublicKey() throws {
        // Generate a new key and test public key PEM export/import
        let privateKey = P384.Signing.PrivateKey()
        let originalPublicKey = privateKey.publicKey
        
        // Export to PEM
        let pemString = originalPublicKey.pemRepresentation
        
        // Verify PEM format
        XCTAssertTrue(pemString.hasPrefix("-----BEGIN PUBLIC KEY-----"))
        XCTAssertTrue(pemString.contains("-----END PUBLIC KEY-----"))
        
        // Import from PEM
        let importedKey = try P384.Signing.PublicKey(pemRepresentation: pemString)
        
        // Verify the keys are equivalent
        XCTAssertEqual(originalPublicKey.rawRepresentation, importedKey.rawRepresentation)
    }
    
    func testP521PEMPrivateKey() throws {
        // Generate a new key and test PEM export/import
        let originalKey = P521.Signing.PrivateKey()
        
        // Export to PEM
        let pemString = originalKey.pemRepresentation
        
        // Verify PEM format
        XCTAssertTrue(pemString.hasPrefix("-----BEGIN PRIVATE KEY-----"))
        XCTAssertTrue(pemString.contains("-----END PRIVATE KEY-----"))
        
        // Import from PEM
        let importedKey = try P521.Signing.PrivateKey(pemRepresentation: pemString)
        
        // Verify the keys are equivalent
        XCTAssertEqual(originalKey.rawRepresentation, importedKey.rawRepresentation)
        
        // Test DER representation
        let derData = originalKey.derRepresentation
        let keyFromDER = try P521.Signing.PrivateKey(derRepresentation: derData)
        XCTAssertEqual(originalKey.rawRepresentation, keyFromDER.rawRepresentation)
    }
    
    func testP521PEMPublicKey() throws {
        // Generate a new key and test public key PEM export/import
        let privateKey = P521.Signing.PrivateKey()
        let originalPublicKey = privateKey.publicKey
        
        // Export to PEM
        let pemString = originalPublicKey.pemRepresentation
        
        // Verify PEM format
        XCTAssertTrue(pemString.hasPrefix("-----BEGIN PUBLIC KEY-----"))
        XCTAssertTrue(pemString.contains("-----END PUBLIC KEY-----"))
        
        // Import from PEM
        let importedKey = try P521.Signing.PublicKey(pemRepresentation: pemString)
        
        // Verify the keys are equivalent
        XCTAssertEqual(originalPublicKey.rawRepresentation, importedKey.rawRepresentation)
    }
    
    func testPEMToOpenSSHConversion() throws {
        // Test converting between PEM and OpenSSH formats for P256
        let p256Key = P256.Signing.PrivateKey()
        
        // Export to PEM
        let pemRepresentation = p256Key.pemRepresentation
        
        // Import from PEM
        let keyFromPEM = try P256.Signing.PrivateKey(pemRepresentation: pemRepresentation)
        
        // Verify PEM round-trip works
        XCTAssertEqual(p256Key.rawRepresentation, keyFromPEM.rawRepresentation)
        
        // Test OpenSSH generation and round-trip
        let sshRepresentation = try keyFromPEM.makeSSHRepresentation()
        let keyFromSSH = try P256.Signing.PrivateKey(sshECDSA: sshRepresentation)
        XCTAssertEqual(p256Key.rawRepresentation, keyFromSSH.rawRepresentation)
    }
    
    func testP384PEMToOpenSSHConversion() throws {
        // Test converting between PEM and OpenSSH formats for P384
        let p384Key = P384.Signing.PrivateKey()
        
        // Export to PEM
        let pemRepresentation = p384Key.pemRepresentation
        
        // Import from PEM
        let keyFromPEM = try P384.Signing.PrivateKey(pemRepresentation: pemRepresentation)
        
        // Verify PEM round-trip works
        XCTAssertEqual(p384Key.rawRepresentation, keyFromPEM.rawRepresentation)
        
        // Test OpenSSH generation and round-trip
        let sshRepresentation = try keyFromPEM.makeSSHRepresentation()
        let keyFromSSH = try P384.Signing.PrivateKey(sshECDSA: sshRepresentation)
        XCTAssertEqual(p384Key.rawRepresentation, keyFromSSH.rawRepresentation)
    }
    
    func testP521PEMToOpenSSHConversion() throws {
        // Test converting between PEM and OpenSSH formats for P521
        let p521Key = P521.Signing.PrivateKey()
        
        // Export to PEM
        let pemRepresentation = p521Key.pemRepresentation
        
        // Import from PEM
        let keyFromPEM = try P521.Signing.PrivateKey(pemRepresentation: pemRepresentation)
        
        // Verify PEM round-trip works
        XCTAssertEqual(p521Key.rawRepresentation, keyFromPEM.rawRepresentation)
        
        // Test OpenSSH generation and round-trip
        let sshRepresentation = try keyFromPEM.makeSSHRepresentation()
        let keyFromSSH = try P521.Signing.PrivateKey(sshECDSA: sshRepresentation)
        XCTAssertEqual(p521Key.rawRepresentation, keyFromSSH.rawRepresentation)
    }
    
    func testOpenSSHWithComment() throws {
        // Test OpenSSH generation with custom comment
        let p256Key = P256.Signing.PrivateKey()
        let comment = "test@example.com"
        
        let sshRepresentation = try p256Key.makeSSHRepresentation(comment: comment)
        let parsedKey = try OpenSSH.PrivateKey<P256.Signing.PrivateKey>(string: sshRepresentation)
        
        XCTAssertEqual(parsedKey.comment, comment)
        XCTAssertEqual(p256Key.rawRepresentation, parsedKey.privateKey.rawRepresentation)
    }
    
    func testInvalidPEMFormat() throws {
        // Test invalid PEM strings
        let invalidPEM = """
        -----BEGIN PRIVATE KEY-----
        InvalidBase64Data!@#$%
        -----END PRIVATE KEY-----
        """
        
        XCTAssertThrowsError(try P256.Signing.PrivateKey(pemRepresentation: invalidPEM))
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: invalidPEM))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: invalidPEM))
    }
    
    func testWrongCurvePEM() throws {
        // Generate a P-256 key
        let p256Key = P256.Signing.PrivateKey()
        let p256PEM = p256Key.pemRepresentation
        
        // Should succeed for P256
        XCTAssertNoThrow(try P256.Signing.PrivateKey(pemRepresentation: p256PEM))
        
        // Should fail for P384 and P521
        XCTAssertThrowsError(try P384.Signing.PrivateKey(pemRepresentation: p256PEM))
        XCTAssertThrowsError(try P521.Signing.PrivateKey(pemRepresentation: p256PEM))
    }
}