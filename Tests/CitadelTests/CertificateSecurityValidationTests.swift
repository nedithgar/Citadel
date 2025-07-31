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
        
        // Should fail with empty principals (OpenSSH behavior)
        XCTAssertThrowsError(try certificate.validatePrincipal(username: "anyuser")) { error in
            guard case SSHCertificateError.noPrincipalsSpecified = error else {
                XCTFail("Expected noPrincipalsSpecified error, got \(error)")
                return
            }
        }
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
        
        let constraints = CertificateConstraints(from: certificate.criticalOptions)
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
    
    func testCriticalOptions_Restrictions() throws {
        let certificate = createTestCertificate(
            criticalOptions: [
                ("no-pty", Data()),
                ("no-port-forwarding", Data()),
                ("no-x11-forwarding", Data())
            ]
        )
        
        let constraints = CertificateConstraints(from: certificate.criticalOptions)
        XCTAssertFalse(constraints.permitPTY)
        XCTAssertFalse(constraints.permitPortForwarding)
        XCTAssertFalse(constraints.permitX11Forwarding)
        XCTAssertTrue(constraints.permitAgentForwarding)  // Not restricted
        XCTAssertTrue(constraints.permitUserRC)  // Not restricted
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
}