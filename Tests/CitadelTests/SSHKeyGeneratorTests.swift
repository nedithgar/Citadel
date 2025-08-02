import XCTest
@testable import Citadel
import Crypto
import _CryptoExtras
import NIOSSH
import NIOCore

final class SSHKeyGeneratorTests: XCTestCase {
    
    // MARK: - RSA Key Generation Tests
    
    func testGenerateRSA2048() throws {
        let keyPair = SSHKeyGenerator.generateRSA(bits: 2048)
        
        // Verify key type
        guard case .rsa(let bits) = keyPair.keyType else {
            XCTFail("Expected RSA key type")
            return
        }
        XCTAssertEqual(bits, 2048)
        
        // Verify key types
        XCTAssertNotNil(keyPair.nioSSHPrivateKey)
        XCTAssertNotNil(keyPair.nioSSHPrivateKey.publicKey)
        
        // Test public key export
        let publicKeyString = try keyPair.publicKeyOpenSSHString()
        XCTAssertTrue(publicKeyString.hasPrefix("ssh-rsa "))
        XCTAssertTrue(publicKeyString.split(separator: " ").count >= 2)
        
        // Verify base64 encoding
        let components = publicKeyString.split(separator: " ")
        let base64Data = Data(base64Encoded: String(components[1]))
        XCTAssertNotNil(base64Data)
    }
    
    func testGenerateRSA4096() throws {
        let keyPair = SSHKeyGenerator.generateRSA(bits: 4096)
        
        guard case .rsa(let bits) = keyPair.keyType else {
            XCTFail("Expected RSA key type")
            return
        }
        XCTAssertEqual(bits, 4096)
    }
    
    func testRSAOpenSSHFormat() throws {
        let keyPair = SSHKeyGenerator.generateRSA(bits: 2048)
        
        // Test unencrypted export
        let privateKey = try keyPair.privateKeyOpenSSHString()
        XCTAssertTrue(privateKey.contains("BEGIN OPENSSH PRIVATE KEY"))
        XCTAssertTrue(privateKey.contains("END OPENSSH PRIVATE KEY"))
        
        // Test with comment
        let privateKeyWithComment = try keyPair.privateKeyOpenSSHString(comment: "test@example.com")
        XCTAssertTrue(privateKeyWithComment.contains("BEGIN OPENSSH PRIVATE KEY"))
        
        // Test with passphrase
        let encryptedKey = try keyPair.privateKeyOpenSSHString(
            comment: "test@example.com",
            passphrase: "secret123"
        )
        XCTAssertTrue(encryptedKey.contains("BEGIN OPENSSH PRIVATE KEY"))
        
        // Test with custom cipher
        let customCipherKey = try keyPair.privateKeyOpenSSHString(
            comment: "test@example.com",
            passphrase: "secret123",
            cipher: "aes128-ctr"
        )
        XCTAssertTrue(customCipherKey.contains("BEGIN OPENSSH PRIVATE KEY"))
    }
    
    // MARK: - Ed25519 Key Generation Tests
    
    func testGenerateEd25519() throws {
        let keyPair = SSHKeyGenerator.generateEd25519()
        
        // Verify key type
        guard case .ed25519 = keyPair.keyType else {
            XCTFail("Expected Ed25519 key type")
            return
        }
        
        // Verify key types
        XCTAssertNotNil(keyPair.nioSSHPrivateKey)
        XCTAssertNotNil(keyPair.nioSSHPrivateKey.publicKey)
        
        // Test public key export
        let publicKeyString = try keyPair.publicKeyOpenSSHString()
        XCTAssertTrue(publicKeyString.hasPrefix("ssh-ed25519 "))
        
        // Test private key export
        let privateKeyString = try keyPair.privateKeyOpenSSHString(comment: "test@example.com")
        XCTAssertTrue(privateKeyString.contains("BEGIN OPENSSH PRIVATE KEY"))
        XCTAssertTrue(privateKeyString.contains("END OPENSSH PRIVATE KEY"))
        
        // Test with passphrase
        let encryptedKey = try keyPair.privateKeyOpenSSHString(comment: "test", passphrase: "secret123")
        XCTAssertTrue(encryptedKey.contains("BEGIN OPENSSH PRIVATE KEY"))
    }
    
    // MARK: - ECDSA Key Generation Tests
    
    func testGenerateECDSAP256() throws {
        let keyPair = SSHKeyGenerator.generateECDSA(curve: .p256)
        
        // Verify key type
        guard case .ecdsaP256 = keyPair.keyType else {
            XCTFail("Expected ECDSA P256 key type")
            return
        }
        
        // Verify key types
        XCTAssertNotNil(keyPair.nioSSHPrivateKey)
        XCTAssertNotNil(keyPair.nioSSHPrivateKey.publicKey)
        
        // Test public key export
        let publicKeyString = try keyPair.publicKeyOpenSSHString()
        XCTAssertTrue(publicKeyString.hasPrefix("ecdsa-sha2-nistp256 "))
        
        // Test private key export
        let privateKeyString = try keyPair.privateKeyOpenSSHString()
        XCTAssertTrue(privateKeyString.contains("BEGIN OPENSSH PRIVATE KEY"))
        
        // Test PEM export
        let pemString = try keyPair.privateKeyPEMString()
        XCTAssertNotNil(pemString)
        XCTAssertTrue(pemString!.contains("BEGIN EC PRIVATE KEY") || pemString!.contains("BEGIN PRIVATE KEY"))
    }
    
    func testGenerateECDSAP384() throws {
        let keyPair = SSHKeyGenerator.generateECDSA(curve: .p384)
        
        guard case .ecdsaP384 = keyPair.keyType else {
            XCTFail("Expected ECDSA P384 key type")
            return
        }
        
        XCTAssertNotNil(keyPair.nioSSHPrivateKey)
        let publicKeyString = try keyPair.publicKeyOpenSSHString()
        XCTAssertTrue(publicKeyString.hasPrefix("ecdsa-sha2-nistp384 "))
        
        // Test PEM export
        let pemString = try keyPair.privateKeyPEMString()
        XCTAssertNotNil(pemString)
    }
    
    func testGenerateECDSAP521() throws {
        let keyPair = SSHKeyGenerator.generateECDSA(curve: .p521)
        
        guard case .ecdsaP521 = keyPair.keyType else {
            XCTFail("Expected ECDSA P521 key type")
            return
        }
        
        XCTAssertNotNil(keyPair.nioSSHPrivateKey)
        let publicKeyString = try keyPair.publicKeyOpenSSHString()
        XCTAssertTrue(publicKeyString.hasPrefix("ecdsa-sha2-nistp521 "))
        
        // Test PEM export
        let pemString = try keyPair.privateKeyPEMString()
        XCTAssertNotNil(pemString)
    }
    
    // MARK: - Generic Generate Method Tests
    
    func testGenerateWithDefaultType() throws {
        let keyPair = SSHKeyGenerator.generate()
        
        // Default should be Ed25519
        guard case .ed25519 = keyPair.keyType else {
            XCTFail("Expected Ed25519 as default key type")
            return
        }
    }
    
    func testGenerateWithSpecificTypes() throws {
        // Test each type through the generic method
        let rsaKeyPair = SSHKeyGenerator.generate(type: .rsa(bits: 3072))
        guard case .rsa(let bits) = rsaKeyPair.keyType else {
            XCTFail("Expected RSA key type")
            return
        }
        XCTAssertEqual(bits, 3072)
        
        let ed25519KeyPair = SSHKeyGenerator.generate(type: .ed25519)
        guard case .ed25519 = ed25519KeyPair.keyType else {
            XCTFail("Expected Ed25519 key type")
            return
        }
        
        let p256KeyPair = SSHKeyGenerator.generate(type: .ecdsaP256)
        guard case .ecdsaP256 = p256KeyPair.keyType else {
            XCTFail("Expected ECDSA P256 key type")
            return
        }
    }
    
    // MARK: - Key Uniqueness Tests
    
    func testGeneratedKeysAreUnique() throws {
        // Generate multiple keys of the same type and verify they're different
        let key1 = SSHKeyGenerator.generateEd25519()
        let key2 = SSHKeyGenerator.generateEd25519()
        
        let publicKey1 = try key1.publicKeyOpenSSHString()
        let publicKey2 = try key2.publicKeyOpenSSHString()
        
        XCTAssertNotEqual(publicKey1, publicKey2, "Generated keys should be unique")
    }
    
    // MARK: - Export Format Tests
    
    func testPublicKeyExportFormat() throws {
        // Test that all key types produce valid OpenSSH public key format
        let keyTypes: [SSHKeyGenerationType] = [
            .rsa(bits: 2048),
            .ed25519,
            .ecdsaP256,
            .ecdsaP384,
            .ecdsaP521
        ]
        
        for keyType in keyTypes {
            let keyPair = SSHKeyGenerator.generate(type: keyType)
            let publicKey = try keyPair.publicKeyOpenSSHString()
            
            // Verify format: "algorithm base64data"
            let components = publicKey.split(separator: " ")
            XCTAssertGreaterThanOrEqual(components.count, 2, "Public key should have at least algorithm and data")
            
            // Verify base64 decoding works
            let base64Data = Data(base64Encoded: String(components[1]))
            XCTAssertNotNil(base64Data, "Public key data should be valid base64")
            XCTAssertGreaterThan(base64Data!.count, 0, "Public key data should not be empty")
        }
    }
    
    func testPEMExportSupport() throws {
        // Ed25519 now supports PEM
        let ed25519 = SSHKeyGenerator.generateEd25519()
        let ed25519PEM = try ed25519.privateKeyPEMString()
        XCTAssertNotNil(ed25519PEM)
        XCTAssertTrue(ed25519PEM!.contains("-----BEGIN PRIVATE KEY-----"))
        XCTAssertTrue(ed25519PEM!.contains("-----END PRIVATE KEY-----"))
        
        // RSA now supports PEM
        let rsa = SSHKeyGenerator.generateRSA()
        let rsaPEM = try rsa.privateKeyPEMString()
        XCTAssertNotNil(rsaPEM)
        XCTAssertTrue(rsaPEM!.contains("-----BEGIN RSA PRIVATE KEY-----"))
        XCTAssertTrue(rsaPEM!.contains("-----END RSA PRIVATE KEY-----"))
        
        // ECDSA keys should support PEM
        let ecdsaKeys = [
            SSHKeyGenerator.generateECDSA(curve: .p256),
            SSHKeyGenerator.generateECDSA(curve: .p384),
            SSHKeyGenerator.generateECDSA(curve: .p521)
        ]
        
        for keyPair in ecdsaKeys {
            let pem = try keyPair.privateKeyPEMString()
            XCTAssertNotNil(pem)
            XCTAssertTrue(pem!.contains("BEGIN") && pem!.contains("END"))
        }
    }
    
    func testPrivateKeyExportWithCipher() throws {
        // Test Ed25519 key with different ciphers
        let ed25519 = SSHKeyGenerator.generateEd25519()
        
        // Test with no passphrase (should use "none" cipher)
        let unencrypted = try ed25519.privateKeyOpenSSHString()
        XCTAssertTrue(unencrypted.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))
        
        // Test with passphrase but no cipher specified (should default to aes256-ctr)
        let defaultCipher = try ed25519.privateKeyOpenSSHString(passphrase: "test123")
        XCTAssertTrue(defaultCipher.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))
        
        // Test with passphrase and explicit aes128-ctr cipher
        let aes128 = try ed25519.privateKeyOpenSSHString(passphrase: "test123", cipher: "aes128-ctr")
        XCTAssertTrue(aes128.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))
        
        // Test with passphrase and explicit aes256-ctr cipher
        let aes256 = try ed25519.privateKeyOpenSSHString(passphrase: "test123", cipher: "aes256-ctr")
        XCTAssertTrue(aes256.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))
        
        // Test with passphrase but explicit "none" cipher (unencrypted despite passphrase)
        let noCipher = try ed25519.privateKeyOpenSSHString(passphrase: "test123", cipher: "none")
        XCTAssertTrue(noCipher.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))
        
        // Test ECDSA key with cipher
        let ecdsa = SSHKeyGenerator.generateECDSA(curve: .p256)
        let ecdsaEncrypted = try ecdsa.privateKeyOpenSSHString(passphrase: "test456", cipher: "aes128-ctr")
        XCTAssertTrue(ecdsaEncrypted.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))
    }
    
    // MARK: - RSA PEM Export/Import Tests
    
    func testRSAPEMExportImportRoundtrip() throws {
        // Test various RSA key sizes
        let keySizes = [2048, 3072, 4096]
        
        for bits in keySizes {
            // Generate RSA key
            let originalKeyPair = SSHKeyGenerator.generateRSA(bits: bits)
            
            // Export to PEM using SSHKeyGenerator interface
            let pemString = try originalKeyPair.privateKeyPEMString()
            XCTAssertNotNil(pemString)
            XCTAssertTrue(pemString!.contains("-----BEGIN RSA PRIVATE KEY-----"))
            XCTAssertTrue(pemString!.contains("-----END RSA PRIVATE KEY-----"))
            
            // Import from PEM
            let importedKey = try Insecure.RSA.PrivateKey(pemRepresentation: pemString!)
            
            // Export imported key to PEM again
            let reimportedPEM = try importedKey.pemRepresentation
            
            // Verify both PEMs produce working keys by re-importing and checking
            // Import the re-exported PEM
            let reimportedKey = try Insecure.RSA.PrivateKey(pemRepresentation: reimportedPEM)
            
            // Test data
            let testData = "Test data for signature \(bits) bits".data(using: .utf8)!
            
            // Create signatures using the imported keys directly
            let importedSig = try importedKey.signature(for: testData)
            let reimportedSig = try reimportedKey.signature(for: testData)
            
            // Verify signatures work with their own public keys
            XCTAssertTrue(importedKey.publicKey.isValidSignature(importedSig, for: testData))
            XCTAssertTrue(reimportedKey.publicKey.isValidSignature(reimportedSig, for: testData))
            
            // Cross-verify: keys should validate each other's signatures
            XCTAssertTrue(importedKey.publicKey.isValidSignature(reimportedSig, for: testData))
            XCTAssertTrue(reimportedKey.publicKey.isValidSignature(importedSig, for: testData))
        }
    }
    
    func testRSADERExportImportRoundtrip() throws {
        // Generate a fresh RSA key directly
        let originalKey = Insecure.RSA.PrivateKey(bits: 2048)
        
        // Export to DER
        let derData = try originalKey.derRepresentation
        XCTAssertGreaterThan(derData.count, 0)
        
        // Import from DER
        let importedKey = try Insecure.RSA.PrivateKey(derRepresentation: derData)
        
        // Compare by creating signatures
        let testData = "Test data for DER roundtrip".data(using: .utf8)!
        let originalSig = try originalKey.signature(for: testData)
        let importedSig = try importedKey.signature(for: testData)
        
        // Verify both signatures work
        XCTAssertTrue(originalKey.publicKey.isValidSignature(originalSig, for: testData))
        XCTAssertTrue(importedKey.publicKey.isValidSignature(importedSig, for: testData))
        
        // Cross-verify
        XCTAssertTrue(originalKey.publicKey.isValidSignature(importedSig, for: testData))
        XCTAssertTrue(importedKey.publicKey.isValidSignature(originalSig, for: testData))
        
        // Also test DER -> PEM -> DER roundtrip
        let pemFromDER = try importedKey.pemRepresentation
        let keyFromPEM = try Insecure.RSA.PrivateKey(pemRepresentation: pemFromDER)
        let derFromPEM = try keyFromPEM.derRepresentation
        
        // DER data might not be byte-for-byte identical but should produce equivalent keys
        let finalKey = try Insecure.RSA.PrivateKey(derRepresentation: derFromPEM)
        let finalSig = try finalKey.signature(for: testData)
        XCTAssertTrue(originalKey.publicKey.isValidSignature(finalSig, for: testData))
    }
    
    func testRSAPEMImportFromExternalKey() throws {
        // Generate a valid RSA key, export to PEM, then use that as external
        let generatedKey = Insecure.RSA.PrivateKey(bits: 2048)
        let validPEM = try generatedKey.pemRepresentation
        
        // Now test importing this "external" PEM
        let externalPEM = validPEM
        
        // Import the external key
        let importedKey = try Insecure.RSA.PrivateKey(pemRepresentation: externalPEM)
        
        // Test that we can use it to sign data
        let testData = "Test data for external key".data(using: .utf8)!
        let signature = try importedKey.signature(for: testData)
        
        // Verify the signature
        XCTAssertTrue(importedKey.publicKey.isValidSignature(signature, for: testData))
        
        // Export it back to PEM and verify it's valid
        let reexportedPEM = try importedKey.pemRepresentation
        XCTAssertTrue(reexportedPEM.contains("-----BEGIN RSA PRIVATE KEY-----"))
        XCTAssertTrue(reexportedPEM.contains("-----END RSA PRIVATE KEY-----"))
    }
    
    func testRSAPEMCompatibilityWithSSHKeyGenerator() throws {
        // Generate key using SSHKeyGenerator
        let keyPair = SSHKeyGenerator.generateRSA(bits: 2048)
        
        // Get PEM through SSHKeyGenerator interface
        let pemFromGenerator = try keyPair.privateKeyPEMString()
        XCTAssertNotNil(pemFromGenerator)
        XCTAssertTrue(pemFromGenerator!.contains("-----BEGIN RSA PRIVATE KEY-----"))
        
        // Import the PEM and verify it works
        let keyFromPEM = try Insecure.RSA.PrivateKey(pemRepresentation: pemFromGenerator!)
        
        // Test that the imported key produces valid signatures
        let testData = "Compatibility test".data(using: .utf8)!
        let importedSig = try keyFromPEM.signature(for: testData)
        
        // The imported key should be able to validate its own signature
        XCTAssertTrue(keyFromPEM.publicKey.isValidSignature(importedSig, for: testData))
        
        // Export both to PEM again and they should produce valid PEMs
        let reExportedPEM = try keyFromPEM.pemRepresentation
        XCTAssertTrue(reExportedPEM.contains("-----BEGIN RSA PRIVATE KEY-----"))
        XCTAssertTrue(reExportedPEM.contains("-----END RSA PRIVATE KEY-----"))
        
        // Test OpenSSH format export still works
        let opensshFormat = try keyPair.privateKeyOpenSSHString()
        XCTAssertTrue(opensshFormat.contains("-----BEGIN OPENSSH PRIVATE KEY-----"))
    }
}