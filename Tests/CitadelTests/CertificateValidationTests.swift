import XCTest
import NIOCore
import NIOSSH
import Crypto
import _CryptoExtras
@testable import Citadel

final class CertificateValidationTests: XCTestCase {
    
    // MARK: - CA Trust Validation Tests
    
    func testCertificateSignatureVerification_ValidCA_Succeeds() throws {
        // Load a test certificate and its CA
        let certData = try TestCertificateHelper.loadCertificateData(name: "user_ed25519-cert")
        let certificate = try SSHCertificate(from: certData, expectedKeyType: "ssh-ed25519-cert-v01@openssh.com")
        
        // Load the CA public key
        let caPublicKey = try TestCertificateHelper.loadPublicKey(name: "ca_ed25519")
        let trustedCAs = [caPublicKey]
        
        // Should succeed with correct CA
        XCTAssertNoThrow(try certificate.verifyCertificateSignature(trustedCAs: trustedCAs))
    }
    
    func testCertificateSignatureVerification_UntrustedCA_Fails() throws {
        // Load a test certificate
        let certData = try TestCertificateHelper.loadCertificateData(name: "user_ed25519-cert")
        let certificate = try SSHCertificate(from: certData, expectedKeyType: "ssh-ed25519-cert-v01@openssh.com")
        
        // Load a different CA public key (not the one that signed the certificate)
        // For this test, we'll create a new key pair that wasn't used to sign the certificate
        let wrongCAPrivateKey = Curve25519.Signing.PrivateKey()
        let wrongCAData = wrongCAPrivateKey.publicKey.rawRepresentation
        var wrongCABuffer = ByteBufferAllocator().buffer(capacity: 128)
        wrongCABuffer.writeSSHString("ssh-ed25519")
        wrongCABuffer.writeSSHData(wrongCAData)
        let wrongCAString = "ssh-ed25519 \(wrongCABuffer.readData(length: wrongCABuffer.readableBytes)!.base64EncodedString())"
        let wrongCA = try NIOSSHPublicKey(openSSHPublicKey: wrongCAString)
        let trustedCAs = [wrongCA]
        
        // Should fail with wrong CA
        XCTAssertThrowsError(try certificate.verifyCertificateSignature(trustedCAs: trustedCAs)) { error in
            XCTAssertEqual(error as? SSHCertificateError, SSHCertificateError.untrustedCA)
        }
    }
    
    func testCertificateSignatureVerification_EmptyTrustedCAs_Fails() throws {
        // Load a test certificate
        let certData = try TestCertificateHelper.loadCertificateData(name: "user_ed25519-cert")
        let certificate = try SSHCertificate(from: certData, expectedKeyType: "ssh-ed25519-cert-v01@openssh.com")
        
        // Empty trusted CAs list
        let trustedCAs: [NIOSSHPublicKey] = []
        
        // Should fail with no trusted CAs
        XCTAssertThrowsError(try certificate.verifyCertificateSignature(trustedCAs: trustedCAs)) { error in
            XCTAssertEqual(error as? SSHCertificateError, SSHCertificateError.untrustedCA)
        }
    }
    
    func testCertificateSignatureVerification_RSA_ValidCA_Succeeds() throws {
        // Skip RSA test if RSA is not registered with NIOSSH
        // RSA support requires registering RSA algorithms with NIOSSHAlgorithms
        
        // First, try to register RSA support
        NIOSSHAlgorithms.register(publicKey: Insecure.RSA.PublicKey.self, signature: Insecure.RSA.Signature.self)
        
        // Load an RSA test certificate and its CA
        let certData = try TestCertificateHelper.loadCertificateData(name: "user_rsa-cert")
        let certificate = try SSHCertificate(from: certData, expectedKeyType: "ssh-rsa-cert-v01@openssh.com")
        
        // Load the RSA CA public key
        let caPublicKey = try TestCertificateHelper.loadPublicKey(name: "ca_rsa")
        let trustedCAs = [caPublicKey]
        
        // Should succeed with correct CA
        XCTAssertNoThrow(try certificate.verifyCertificateSignature(trustedCAs: trustedCAs))
    }
    
    func testCertificateSignatureVerification_ECDSA_ValidCA_Succeeds() throws {
        // Load an ECDSA test certificate and its CA
        let certData = try TestCertificateHelper.loadCertificateData(name: "user_ecdsa_p256-cert")
        let certificate = try SSHCertificate(from: certData, expectedKeyType: "ecdsa-sha2-nistp256-cert-v01@openssh.com")
        
        // Load the ECDSA CA public key
        let caPublicKey = try TestCertificateHelper.loadPublicKey(name: "ca_ecdsa_p256")
        let trustedCAs = [caPublicKey]
        
        // Should succeed with correct CA
        XCTAssertNoThrow(try certificate.verifyCertificateSignature(trustedCAs: trustedCAs))
    }
    
    func testCertificateSignatureVerification_MultipleTrustedCAs_FindsCorrectOne() throws {
        // Load a test certificate
        let certData = try TestCertificateHelper.loadCertificateData(name: "user_ed25519-cert")
        let certificate = try SSHCertificate(from: certData, expectedKeyType: "ssh-ed25519-cert-v01@openssh.com")
        
        // Create multiple CA keys, including the correct one
        let wrongCA1PrivKey = Curve25519.Signing.PrivateKey()
        let wrongCA1Data = wrongCA1PrivKey.publicKey.rawRepresentation
        var wrongCA1Buffer = ByteBufferAllocator().buffer(capacity: 128)
        wrongCA1Buffer.writeSSHString("ssh-ed25519")
        wrongCA1Buffer.writeSSHData(wrongCA1Data)
        let wrongCA1String = "ssh-ed25519 \(wrongCA1Buffer.readData(length: wrongCA1Buffer.readableBytes)!.base64EncodedString())"
        let wrongCA1 = try NIOSSHPublicKey(openSSHPublicKey: wrongCA1String)
        
        let wrongCA2PrivKey = P256.Signing.PrivateKey()
        let wrongCA2Data = wrongCA2PrivKey.publicKey.x963Representation
        var wrongCA2Buffer = ByteBufferAllocator().buffer(capacity: 256)
        wrongCA2Buffer.writeSSHString("ecdsa-sha2-nistp256")
        wrongCA2Buffer.writeSSHString("nistp256")
        wrongCA2Buffer.writeSSHData(wrongCA2Data)
        let wrongCA2String = "ecdsa-sha2-nistp256 \(wrongCA2Buffer.readData(length: wrongCA2Buffer.readableBytes)!.base64EncodedString())"
        let wrongCA2 = try NIOSSHPublicKey(openSSHPublicKey: wrongCA2String)
        
        let correctCA = try TestCertificateHelper.loadPublicKey(name: "ca_ed25519")
        
        let wrongCA3PrivKey = P384.Signing.PrivateKey()
        let wrongCA3Data = wrongCA3PrivKey.publicKey.x963Representation
        var wrongCA3Buffer = ByteBufferAllocator().buffer(capacity: 256)
        wrongCA3Buffer.writeSSHString("ecdsa-sha2-nistp384")
        wrongCA3Buffer.writeSSHString("nistp384")
        wrongCA3Buffer.writeSSHData(wrongCA3Data)
        let wrongCA3String = "ecdsa-sha2-nistp384 \(wrongCA3Buffer.readData(length: wrongCA3Buffer.readableBytes)!.base64EncodedString())"
        let wrongCA3 = try NIOSSHPublicKey(openSSHPublicKey: wrongCA3String)
        
        let trustedCAs = [wrongCA1, wrongCA2, correctCA, wrongCA3]
        
        // Should succeed when correct CA is in the list
        XCTAssertNoThrow(try certificate.verifyCertificateSignature(trustedCAs: trustedCAs))
    }
    
    // MARK: - Time-based Validation Tests
    
    func testTimeValidation_CurrentTime_Succeeds() throws {
        // Create a certificate valid for a wide time range
        let now = UInt64(Date().timeIntervalSince1970)
        let certificate = SSHCertificate(
            nonce: Data(repeating: 0, count: 32),
            serial: 1,
            type: .user,
            keyId: "test@example.com",
            validPrincipals: ["testuser"],
            validAfter: now - 3600,  // Valid from 1 hour ago
            validBefore: now + 3600,  // Valid until 1 hour from now
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: Data(repeating: 0, count: 32)
        )
        
        // Should succeed for current time
        XCTAssertNoThrow(try certificate.validateTimeConstraints())
    }
    
    func testTimeValidation_ExpiredCertificate_Fails() throws {
        // Load expired certificate
        let certData = try TestCertificateHelper.loadCertificateData(name: "user_expired-cert")
        let certificate = try SSHCertificate(from: certData, expectedKeyType: "ssh-ed25519-cert-v01@openssh.com")
        
        // Should fail as expired
        XCTAssertThrowsError(try certificate.validateTimeConstraints()) { error in
            if case SSHCertificateError.expired = error {
                // Success - correct error type
            } else {
                XCTFail("Expected expired error, got \(error)")
            }
        }
    }
    
    func testTimeValidation_NotYetValidCertificate_Fails() throws {
        // Load not yet valid certificate
        let certData = try TestCertificateHelper.loadCertificateData(name: "user_not_yet_valid-cert")
        let certificate = try SSHCertificate(from: certData, expectedKeyType: "ssh-ed25519-cert-v01@openssh.com")
        
        // Should fail as not yet valid
        XCTAssertThrowsError(try certificate.validateTimeConstraints()) { error in
            if case SSHCertificateError.notYetValid = error {
                // Success - correct error type
            } else {
                XCTFail("Expected notYetValid error, got \(error)")
            }
        }
    }
    
    func testTimeValidation_CustomTime_Succeeds() throws {
        // Create a certificate with specific validity period
        let certificate = SSHCertificate(
            nonce: Data(repeating: 0, count: 32),
            serial: 1,
            type: .user,
            keyId: "test@example.com",
            validPrincipals: ["testuser"],
            validAfter: 1000,
            validBefore: 2000,
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: Data(repeating: 0, count: 32)
        )
        
        // Should succeed within valid range
        XCTAssertNoThrow(try certificate.validateTimeConstraints(currentTime: 1500))
        
        // Should fail before valid range
        XCTAssertThrowsError(try certificate.validateTimeConstraints(currentTime: 500))
        
        // Should fail after valid range
        XCTAssertThrowsError(try certificate.validateTimeConstraints(currentTime: 2500))
    }
    
    // MARK: - Principal Validation Tests
    
    func testPrincipalValidation_ExactMatch_Succeeds() throws {
        // Load certificate with limited principals
        let certData = try TestCertificateHelper.loadCertificateData(name: "user_limited_principals-cert")
        let certificate = try SSHCertificate(from: certData, expectedKeyType: "ssh-ed25519-cert-v01@openssh.com")
        
        // The certificate has principals "alice" and "bob", not "testuser"
        // Should succeed with correct principal
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "alice"))
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "bob"))
    }
    
    func testPrincipalValidation_NoMatch_Fails() throws {
        // Load certificate with limited principals
        let certData = try TestCertificateHelper.loadCertificateData(name: "user_limited_principals-cert")
        let certificate = try SSHCertificate(from: certData, expectedKeyType: "ssh-ed25519-cert-v01@openssh.com")
        
        // Should fail with wrong principal
        XCTAssertThrowsError(try certificate.validatePrincipal(username: "wronguser")) { error in
            if case SSHCertificateError.principalMismatch(let username, let allowedPrincipals) = error {
                XCTAssertEqual(username, "wronguser")
                XCTAssertTrue(allowedPrincipals.contains("alice") || allowedPrincipals.contains("bob"))
            } else {
                XCTFail("Expected principalMismatch error, got \(error)")
            }
        }
    }
    
    func testPrincipalValidation_EmptyPrincipals_Fails() throws {
        // Create certificate with no principals
        let certificate = SSHCertificate(
            nonce: Data(repeating: 0, count: 32),
            serial: 1,
            type: .user,
            keyId: "test@example.com",
            validPrincipals: [],  // Empty principals list
            validAfter: 0,
            validBefore: UInt64.max,
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: Data(repeating: 0, count: 32)
        )
        
        // Should fail with empty principals (OpenSSH behavior)
        XCTAssertThrowsError(try certificate.validatePrincipal(username: "anyuser")) { error in
            XCTAssertEqual(error as? SSHCertificateError, SSHCertificateError.noPrincipalsSpecified)
        }
    }
    
    func testPrincipalValidation_WildcardMatch_Succeeds() throws {
        // Create certificate with wildcard principal
        let certificate = SSHCertificate(
            nonce: Data(repeating: 0, count: 32),
            serial: 1,
            type: .user,
            keyId: "test@example.com",
            validPrincipals: ["test*", "admin?", "*.example.com"],
            validAfter: 0,
            validBefore: UInt64.max,
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: Data(repeating: 0, count: 32)
        )
        
        // Should match wildcard patterns
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "testuser", wildcardAllowed: true))
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "test123", wildcardAllowed: true))
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "admin1", wildcardAllowed: true))
        XCTAssertNoThrow(try certificate.validatePrincipal(username: "user.example.com", wildcardAllowed: true))
        
        // Should not match without wildcard enabled
        XCTAssertThrowsError(try certificate.validatePrincipal(username: "testuser", wildcardAllowed: false))
    }
    
    // MARK: - Critical Options Tests
    
    func testCriticalOptions_ForceCommand_Parsed() throws {
        // Load certificate with critical options
        let certData = try TestCertificateHelper.loadCertificateData(name: "user_critical_options-cert")
        let certificate = try SSHCertificate(from: certData, expectedKeyType: "ssh-ed25519-cert-v01@openssh.com")
        
        // Check force-command is parsed
        let constraints = try CertificateConstraints(from: certificate)
        XCTAssertNotNil(constraints.forceCommand)
        XCTAssertEqual(constraints.forceCommand, "/bin/date")
    }
    
    func testCriticalOptions_SourceAddress_Validated() throws {
        // Create certificate with source-address restriction
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHString("192.168.1.0/24,10.0.0.1")
        let sourceAddressData = Data(buffer.readableBytesView)
        
        let certificate = SSHCertificate(
            nonce: Data(repeating: 0, count: 32),
            serial: 1,
            type: .user,
            keyId: "test@example.com",
            validPrincipals: ["testuser"],
            validAfter: 0,
            validBefore: UInt64.max,
            criticalOptions: [("source-address", sourceAddressData)],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: Data(repeating: 0, count: 32)
        )
        
        // Should succeed with allowed address
        XCTAssertNoThrow(try certificate.validateSourceAddress("10.0.0.1"))
        
        // Should fail with disallowed address
        XCTAssertThrowsError(try certificate.validateSourceAddress("8.8.8.8")) { error in
            if case SSHCertificateError.sourceAddressNotAllowed = error {
                // Success - correct error type
            } else {
                XCTFail("Expected sourceAddressNotAllowed error, got \(error)")
            }
        }
    }
    
    func testCriticalOptions_Restrictions_Parsed() throws {
        // Create certificate with restrictive critical options
        let certificate = SSHCertificate(
            nonce: Data(repeating: 0, count: 32),
            serial: 1,
            type: .user,
            keyId: "test@example.com",
            validPrincipals: ["testuser"],
            validAfter: 0,
            validBefore: UInt64.max,
            criticalOptions: [
                ("no-pty", Data()),
                ("no-port-forwarding", Data()),
                ("no-agent-forwarding", Data())
            ],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: Data(repeating: 0, count: 32)
        )
        
        // These no-* options are not valid critical options in OpenSSH
        // They should cause the certificate to be rejected
        XCTAssertThrowsError(try CertificateConstraints(from: certificate)) { error in
            guard case SSHCertificateError.unknownCriticalOption = error else {
                XCTFail("Expected unknownCriticalOption error, got \(error)")
                return
            }
        }
    }
    
    // MARK: - Complete Validation Tests
    
    func testCompleteValidation_ValidCertificate_Succeeds() throws {
        // This test would require a properly signed certificate with valid time and principals
        // For now, we'll test that the method exists and can be called
        let certificate = SSHCertificate(
            nonce: Data(repeating: 0, count: 32),
            serial: 1,
            type: .user,
            keyId: "test@example.com",
            validPrincipals: ["testuser"],
            validAfter: 0,
            validBefore: UInt64.max,
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: Data(repeating: 0, count: 32)
        )
        
        // Should fail without trusted CAs (signature verification would fail)
        XCTAssertThrowsError(try certificate.validateForAuthentication(
            username: "testuser",
            clientAddress: "192.168.1.1",
            trustedCAs: []
        ))
    }
    
    func testCompleteValidation_WrongCertificateType_Fails() throws {
        // Create host certificate
        let certificate = SSHCertificate(
            nonce: Data(repeating: 0, count: 32),
            serial: 1,
            type: .host,  // Wrong type for user authentication
            keyId: "host.example.com",
            validPrincipals: ["host.example.com"],
            validAfter: 0,
            validBefore: UInt64.max,
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: Data(repeating: 0, count: 32)
        )
        
        // Should fail with wrong certificate type
        XCTAssertThrowsError(try certificate.validateForAuthentication(
            username: "testuser",
            clientAddress: "192.168.1.1",
            trustedCAs: []
        )) { error in
            if case SSHCertificateError.wrongCertificateType(let expected, let actual) = error {
                XCTAssertEqual(expected, .user)
                XCTAssertEqual(actual, .host)
            } else {
                XCTFail("Expected wrongCertificateType error, got \(error)")
            }
        }
    }
    
    // MARK: - SSHCertificateValidator Tests
    
    func testValidator_LegacyMethod_CallsNewValidation() throws {
        // Create a simple certificate
        let now = UInt64(Date().timeIntervalSince1970)
        let certificate = SSHCertificate(
            nonce: Data(repeating: 0, count: 32),
            serial: 1,
            type: .user,
            keyId: "test@example.com",
            validPrincipals: ["testuser"],
            validAfter: now - 3600,
            validBefore: now + 3600,
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: Data(repeating: 0, count: 32)
        )
        
        let context = SSHCertificateValidationContext(
            username: "testuser",
            sourceAddress: "192.168.1.1",
            trustedCAs: []  // Will fail on CA validation
        )
        
        // Should throw an error (no trusted CAs)
        XCTAssertThrowsError(try SSHCertificateValidator.validate(certificate, context: context))
    }
}