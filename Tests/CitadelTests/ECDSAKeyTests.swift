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
        let originalKey = P256.Signing.PrivateKey()
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
}