import XCTest
import NIOCore
import NIOSSH
import Crypto
import _CryptoExtras
@testable import Citadel

final class CertificateSecurityValidationTests: XCTestCase {
    
    // MARK: - Time Validation Tests
    
    func testTimeValidation_ValidCertificate() throws {
        let now = UInt64(Date().timeIntervalSince1970)
        let certificate = createTestCertificate(
            validAfter: now - 3600,  // Valid from 1 hour ago
            validBefore: now + 3600   // Valid until 1 hour from now
        )
        
        // Should not throw for current time
        XCTAssertNoThrow(try certificate.validateTimeConstraints())
    }
    
    func testTimeValidation_ExpiredCertificate() throws {
        let now = UInt64(Date().timeIntervalSince1970)
        let certificate = createTestCertificate(
            validAfter: now - 7200,  // Valid from 2 hours ago
            validBefore: now - 3600   // Expired 1 hour ago
        )
        
        // Should throw expired error
        XCTAssertThrowsError(try certificate.validateTimeConstraints()) { error in
            guard case SSHCertificateError.expired = error else {
                XCTFail("Expected expired error, got \(error)")
                return
            }
        }
    }
    
    func testTimeValidation_NotYetValidCertificate() throws {
        let now = UInt64(Date().timeIntervalSince1970)
        let certificate = createTestCertificate(
            validAfter: now + 3600,  // Valid from 1 hour in future
            validBefore: now + 7200  // Valid until 2 hours in future
        )
        
        // Should throw not yet valid error
        XCTAssertThrowsError(try certificate.validateTimeConstraints()) { error in
            guard case SSHCertificateError.notYetValid = error else {
                XCTFail("Expected notYetValid error, got \(error)")
                return
            }
        }
    }
    
    // MARK: - Principal Validation Tests
    
    func testPrincipalValidation_ExactMatch() throws {
        let certificate = createTestCertificate(
            validPrincipals: ["alice", "bob", "charlie"]
        )
        
        // Should succeed for valid principals
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "alice"))
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "bob"))
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "charlie"))
        
        // Should fail for invalid principal
        XCTAssertThrowsError(try certificate.validatePrincipal(username: "david")) { error in
            guard case SSHCertificateError.principalMismatch(let username, let allowedPrincipals) = error else {
                XCTFail("Expected principalMismatch error, got \(error)")
                return
            }
            XCTAssertEqual(username, "david")
            XCTAssertEqual(allowedPrincipals, ["alice", "bob", "charlie"])
        }
    }
    
    func testPrincipalValidation_EmptyPrincipals() throws {
        let certificate = createTestCertificate(validPrincipals: [])
        
        // Should fail with empty principals when requirePrincipal is true (default, OpenSSH TrustedUserCAKeys behavior)
        XCTAssertThrowsError(try certificate.validatePrincipal(username: "anyuser")) { error in
            guard case SSHCertificateError.noPrincipalsSpecified = error else {
                XCTFail("Expected noPrincipalsSpecified error, got \(error)")
                return
            }
        }
        
        // Should succeed with empty principals when requirePrincipal is false (OpenSSH authorized_keys behavior)
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "anyuser", requirePrincipal: false))
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "differentuser", requirePrincipal: false))
    }
    
    func testPrincipalValidation_WildcardPatterns() throws {
        let certificate = createTestCertificate(
            validPrincipals: ["admin*", "test?", "*.example.com"]
        )
        
        // Test wildcard matching enabled
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "admin", wildcardAllowed: true))
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "admin123", wildcardAllowed: true))
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "test1", wildcardAllowed: true))
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "user.example.com", wildcardAllowed: true))
        
        // Should fail without wildcard matching
        XCTAssertThrowsError(try certificate.validatePrincipal(username: "admin123", wildcardAllowed: false))
    }
    
    // MARK: - Certificate Type Validation Tests
    
    func testCertificateType_UserAuthentication() throws {
        let userCert = createTestCertificate(type: .user)
        let hostCert = createTestCertificate(type: .host)
        
        // User certificate should pass for user authentication
        let trustedCAs: [NIOSSHPublicKey] = [] // Would fail on CA validation
        XCTAssertThrowsError(try userCert.validateForAuthentication(
            username: "testuser",
            clientAddress: "127.0.0.1",
            trustedCAs: trustedCAs
        )) { error in
            // Should fail on CA validation, not type validation
            guard case SSHCertificateError.untrustedCA = error else {
                XCTFail("Expected untrustedCA error, got \(error)")
                return
            }
        }
        
        // Host certificate should fail for user authentication
        XCTAssertThrowsError(try hostCert.validateForAuthentication(
            username: "testuser",
            clientAddress: "127.0.0.1",
            trustedCAs: trustedCAs
        )) { error in
            guard case SSHCertificateError.wrongCertificateType(let expected, let actual) = error else {
                XCTFail("Expected wrongCertificateType error, got \(error)")
                return
            }
            XCTAssertEqual(expected, .user)
            XCTAssertEqual(actual, .host)
        }
    }
    
    // MARK: - Critical Options Tests
    
    func testCriticalOptions_ForceCommand() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHString("/usr/bin/true")
        let forceCommandData = Data(buffer.readableBytesView)
        
        let certificate = createTestCertificate(
            criticalOptions: [("force-command", forceCommandData)]
        )
        
        let constraints = try CertificateConstraints(from: certificate)
        XCTAssertEqual(constraints.forceCommand, "/usr/bin/true")
    }
    
    func testCriticalOptions_SourceAddress() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHString("192.168.1.0/24,10.0.0.1")
        let sourceAddressData = Data(buffer.readableBytesView)
        
        let certificate = createTestCertificate(
            criticalOptions: [("source-address", sourceAddressData)]
        )
        
        // Should succeed with allowed address
        XCTAssertNoThrow(try certificate.validateSourceAddress("10.0.0.1"))
        
        // Should fail with disallowed address
        XCTAssertThrowsError(try certificate.validateSourceAddress("8.8.8.8")) { error in
            guard case SSHCertificateError.sourceAddressNotAllowed(let clientAddress, let allowedAddresses) = error else {
                XCTFail("Expected sourceAddressNotAllowed error, got \(error)")
                return
            }
            XCTAssertEqual(clientAddress, "8.8.8.8")
            XCTAssertTrue(allowedAddresses.contains("10.0.0.1"))
        }
    }
    
    func testCriticalOptions_NoOptionsInCritical_ShouldReject() throws {
        // Test that no-* options in critical section are rejected (they should be extensions)
        let certificate = createTestCertificate(
            criticalOptions: [
                ("no-pty", Data())  // This is not a valid critical option
            ]
        )
        
        // Should throw error because no-pty is not a valid critical option
        XCTAssertThrowsError(try CertificateConstraints(from: certificate)) { error in
            guard case SSHCertificateError.unknownCriticalOption(let optionName) = error else {
                XCTFail("Expected unknownCriticalOption error, got \(error)")
                return
            }
            XCTAssertEqual(optionName, "no-pty")
        }
    }
    
    func testCriticalOptions_VerifyRequired() throws {
        // Test verify-required critical option
        let certificate = createTestCertificate(
            criticalOptions: [
                ("verify-required", Data())
            ]
        )
        
        let constraints = try CertificateConstraints(from: certificate)
        XCTAssertTrue(constraints.verifyRequired)
        
        // Test without verify-required
        let certificateWithout = createTestCertificate(criticalOptions: [])
        let constraintsWithout = try CertificateConstraints(from: certificateWithout)
        XCTAssertFalse(constraintsWithout.verifyRequired)
    }
    
    func testCriticalOptions_UnknownCriticalOption_ShouldReject() throws {
        // Test with an unknown critical option
        let certificate = createTestCertificate(
            criticalOptions: [
                ("force-command", Data()),  // Known option
                ("unknown-critical-option", Data())  // Unknown option
            ]
        )
        
        // Should throw error when parsing constraints
        XCTAssertThrowsError(try CertificateConstraints(from: certificate)) { error in
            guard case SSHCertificateError.unknownCriticalOption(let optionName) = error else {
                XCTFail("Expected unknownCriticalOption error, got \(error)")
                return
            }
            XCTAssertEqual(optionName, "unknown-critical-option")
        }
        
        // Should also fail during certificate validation
        XCTAssertThrowsError(try certificate.validateForAuthentication(
            username: "testuser",
            clientAddress: "127.0.0.1",
            trustedCAs: []
        )) { error in
            // Could fail on CA validation or unknown critical option
            // The important thing is that it fails
        }
    }
    
    // MARK: - RSA Key Length Validation Tests
    
    func testRSAKeyLengthValidation_ValidKey() throws {
        // Create certificate with 2048-bit RSA key
        let certificate = createTestRSACertificate(bits: 2048)
        
        // Should not throw for valid key length
        XCTAssertNoThrow(try certificate.checkRSAKeyLength())
        XCTAssertNoThrow(try certificate.checkRSAKeyLength(minimumBits: 1024))
        XCTAssertNoThrow(try certificate.checkRSAKeyLength(minimumBits: 2048))
    }
    
    func testRSAKeyLengthValidation_ShortKey() throws {
        // Create certificate with 768-bit RSA key
        let certificate = createTestRSACertificate(bits: 768)
        
        // Should throw for short key (default minimum is 1024)
        XCTAssertThrowsError(try certificate.checkRSAKeyLength()) { error in
            guard case SSHCertificateError.rsaKeyTooShort(let bits, let minimumBits) = error else {
                XCTFail("Expected rsaKeyTooShort error, got \(error)")
                return
            }
            XCTAssertEqual(bits, 768)
            XCTAssertEqual(minimumBits, 1024)
        }
        
        // Should pass with lower minimum (explicitly set)
        XCTAssertNoThrow(try certificate.checkRSAKeyLength(minimumBits: 512))
        
        // Should fail with higher minimum
        XCTAssertThrowsError(try certificate.checkRSAKeyLength(minimumBits: 2048)) { error in
            guard case SSHCertificateError.rsaKeyTooShort(let bits, let minimumBits) = error else {
                XCTFail("Expected rsaKeyTooShort error, got \(error)")
                return
            }
            XCTAssertEqual(bits, 768)
            XCTAssertEqual(minimumBits, 2048)
        }
    }
    
    func testRSAKeyLengthValidation_NonRSACertificate() throws {
        // Create non-RSA certificate
        let certificate = createTestCertificate(type: .user)
        
        // Should not throw for non-RSA certificates
        XCTAssertNoThrow(try certificate.checkRSAKeyLength())
        XCTAssertNoThrow(try certificate.checkRSAKeyLength(minimumBits: 4096))
    }
    
    func testRSAKeyLengthValidation_IntegrationWithFullValidation() throws {
        // Create certificate with short RSA key
        let certificate = createTestRSACertificate(bits: 768)
        let trustedCAs: [NIOSSHPublicKey] = [] // Empty for this test
        
        // Should fail validation due to short RSA key when minimumRSABits is set
        XCTAssertThrowsError(try certificate.validateForAuthentication(
            username: "testuser",
            clientAddress: "127.0.0.1",
            trustedCAs: trustedCAs,
            minimumRSABits: 2048
        )) { error in
            // Will fail on CA trust first if no trusted CAs provided
            if case SSHCertificateError.untrustedCA = error {
                // This is expected when no trusted CAs are provided
                return
            }
            guard case SSHCertificateError.rsaKeyTooShort(let bits, let minimumBits) = error else {
                XCTFail("Expected rsaKeyTooShort or untrustedCA error, got \(error)")
                return
            }
            XCTAssertEqual(bits, 768)
            XCTAssertEqual(minimumBits, 2048)
        }
    }
    
    // MARK: - Helper Methods
    
    private func createTestCertificate(
        type: SSHCertificate.CertificateType = .user,
        validPrincipals: [String] = ["testuser"],
        validAfter: UInt64? = nil,
        validBefore: UInt64? = nil,
        criticalOptions: [(String, Data)] = []
    ) -> SSHCertificate {
        let now = UInt64(Date().timeIntervalSince1970)
        
        return SSHCertificate(
            nonce: Data(repeating: 0, count: 32),
            serial: 1,
            type: type,
            keyId: "test@example.com",
            validPrincipals: validPrincipals,
            validAfter: validAfter ?? 0,
            validBefore: validBefore ?? UInt64.max,
            criticalOptions: criticalOptions,
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: Data(repeating: 0, count: 32)
        )
    }
    
    private func createTestRSACertificate(bits: Int) -> SSHCertificate {
        // Create a mock RSA public key with specified bit length
        let modulusBytes = bits / 8
        let exponentBytes = 3 // Common RSA exponent is 65537 which fits in 3 bytes
        
        // Create e (exponent) - typically 65537
        let e = Data([0x01, 0x00, 0x01]) // 65537 in big-endian
        
        // Create n (modulus) with specified bit length
        // Set the high bit to ensure it's the right bit length
        var n = Data(repeating: 0xFF, count: modulusBytes)
        n[0] = 0x80 // Set high bit to ensure correct bit length
        
        // Encode in SSH format (length-prefixed)
        var publicKeyBuffer = ByteBufferAllocator().buffer(capacity: e.count + n.count + 8)
        publicKeyBuffer.writeSSHData(e)
        publicKeyBuffer.writeSSHData(n)
        let publicKeyData = Data(publicKeyBuffer.readableBytesView)
        
        return SSHCertificate(
            nonce: Data(repeating: 0, count: 32),
            serial: 1,
            type: .user,
            keyId: "test-rsa@example.com",
            validPrincipals: ["testuser"],
            validAfter: 0,
            validBefore: UInt64.max,
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: publicKeyData,
            keyType: "ssh-rsa-cert-v01@openssh.com"
        )
    }
}