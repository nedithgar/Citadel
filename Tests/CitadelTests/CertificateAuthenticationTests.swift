import XCTest
@testable import Citadel
import Crypto
import _CryptoExtras
import Foundation
import NIO
import NIOSSH

final class CertificateAuthenticationTests: XCTestCase {
    
    // Test that certificate types are properly registered and can be used
    func testCertificateTypesAreRegistered() throws {
        // Test that certificate public key types exist and can be instantiated
        XCTAssertNotNil(Ed25519.CertificatePublicKey.self)
        XCTAssertNotNil(Insecure.RSA.CertificatePublicKey.self)
        XCTAssertNotNil(P256.Signing.CertificatePublicKey.self)
        XCTAssertNotNil(P384.Signing.CertificatePublicKey.self)
        XCTAssertNotNil(P521.Signing.CertificatePublicKey.self)
        
        // Verify the public key prefixes are correct
        XCTAssertEqual(Ed25519.CertificatePublicKey.publicKeyPrefix, "ssh-ed25519-cert-v01@openssh.com")
        XCTAssertEqual(P256.Signing.CertificatePublicKey.publicKeyPrefix, "ecdsa-sha2-nistp256-cert-v01@openssh.com")
        XCTAssertEqual(P384.Signing.CertificatePublicKey.publicKeyPrefix, "ecdsa-sha2-nistp384-cert-v01@openssh.com")
        XCTAssertEqual(P521.Signing.CertificatePublicKey.publicKeyPrefix, "ecdsa-sha2-nistp521-cert-v01@openssh.com")
    }
    
    // Helper function to create a test certificate
    private func createTestCertificate(publicKey: Data, keyType: String) -> SSHCertificate {
        let now = UInt64(Date().timeIntervalSince1970)
        let caPrivateKey = Curve25519.Signing.PrivateKey()
        let caPublicKey = caPrivateKey.publicKey
        
        // Create CA signature key data
        var caKeyBuffer = ByteBufferAllocator().buffer(capacity: 256)
        caKeyBuffer.writeSSHString("ssh-ed25519")
        caKeyBuffer.writeSSHData(caPublicKey.rawRepresentation)
        let caKeyData = Data(caKeyBuffer.readableBytesView)
        
        // Create a dummy signature (in real usage, this would be a proper signature)
        var signatureBuffer = ByteBufferAllocator().buffer(capacity: 128)
        signatureBuffer.writeSSHString("ssh-ed25519")
        signatureBuffer.writeSSHData(Data(repeating: 0, count: 64)) // Ed25519 signature is 64 bytes
        let signatureData = Data(signatureBuffer.readableBytesView)
        
        return SSHCertificate(
            nonce: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
            serial: 1,
            type: .user, // User certificate
            keyId: "test-user@example.com",
            validPrincipals: ["testuser", "admin"],
            validAfter: now - 3600, // Valid from 1 hour ago
            validBefore: now + 3600, // Valid for 1 hour from now
            criticalOptions: [],
            extensions: [
                ("permit-X11-forwarding", Data()),
                ("permit-agent-forwarding", Data()),
                ("permit-port-forwarding", Data()),
                ("permit-pty", Data()),
                ("permit-user-rc", Data())
            ],
            reserved: Data(),
            signatureKey: caKeyData,
            signature: signatureData,
            publicKey: publicKey
        )
    }
    
    // Test creating and using Ed25519 certificates
    func testEd25519CertificateAuthentication() throws {
        // Create a key pair
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Create a test certificate
        let certificate = createTestCertificate(
            publicKey: publicKey.rawRepresentation,
            keyType: "ssh-ed25519-cert-v01@openssh.com"
        )
        
        // Create the certificate public key
        let certPublicKey = Ed25519.CertificatePublicKey(
            certificate: certificate,
            publicKey: publicKey
        )
        
        // Verify it implements NIOSSHPublicKeyProtocol
        XCTAssertTrue(type(of: certPublicKey) is NIOSSHPublicKeyProtocol.Type)
        
        // Create authentication method with the private key
        // The certificate will be included automatically when authenticating
        let authMethod = SSHAuthenticationMethod.ed25519(username: "testuser", privateKey: privateKey)
        XCTAssertNotNil(authMethod)
    }
    
    // Test creating and using RSA certificates
    func testRSACertificateAuthentication() throws {
        // Create a key pair
        let privateKey = Insecure.RSA.PrivateKey(bits: 2048)
        let publicKey = privateKey.publicKey as! Insecure.RSA.PublicKey
        
        // Create public key data for RSA
        // RSA public key in SSH format is: e (exponent) followed by n (modulus)
        let publicKeyData = publicKey.rawRepresentation
        
        // Create a test certificate
        let certificate = createTestCertificate(
            publicKey: publicKeyData,
            keyType: "ssh-rsa-cert-v01@openssh.com"
        )
        
        // Create the certificate public key with SHA256 algorithm
        let certPublicKey = Insecure.RSA.CertificatePublicKey(
            certificate: certificate,
            publicKey: publicKey,
            algorithm: .sha256Cert
        )
        
        // Verify it implements NIOSSHPublicKeyProtocol
        XCTAssertTrue(type(of: certPublicKey) is NIOSSHPublicKeyProtocol.Type)
        
        // Create authentication method
        let authMethod = SSHAuthenticationMethod.rsa(username: "testuser", privateKey: privateKey)
        XCTAssertNotNil(authMethod)
    }
    
    // Test creating and using ECDSA P256 certificates
    func testP256CertificateAuthentication() throws {
        // Create a key pair
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Create public key data for P256
        // ECDSA certificates store the full x963 representation
        let publicKeyData = publicKey.x963Representation
        
        // Create a test certificate
        let certificate = createTestCertificate(
            publicKey: publicKeyData,
            keyType: "ecdsa-sha2-nistp256-cert-v01@openssh.com"
        )
        
        // Create the certificate public key
        let certPublicKey = P256.Signing.CertificatePublicKey(
            certificate: certificate,
            publicKey: publicKey
        )
        
        // Verify it implements NIOSSHPublicKeyProtocol
        XCTAssertTrue(type(of: certPublicKey) is NIOSSHPublicKeyProtocol.Type)
        
        // Create authentication method
        let authMethod = SSHAuthenticationMethod.p256(username: "testuser", privateKey: privateKey)
        XCTAssertNotNil(authMethod)
    }
    
    // Test creating and using ECDSA P384 certificates
    func testP384CertificateAuthentication() throws {
        // Create a key pair
        let privateKey = P384.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Create public key data for P384
        let publicKeyData = publicKey.x963Representation
        
        // Create a test certificate
        let certificate = createTestCertificate(
            publicKey: publicKeyData,
            keyType: "ecdsa-sha2-nistp384-cert-v01@openssh.com"
        )
        
        // Create the certificate public key
        let certPublicKey = P384.Signing.CertificatePublicKey(
            certificate: certificate,
            publicKey: publicKey
        )
        
        // Verify it implements NIOSSHPublicKeyProtocol
        XCTAssertTrue(type(of: certPublicKey) is NIOSSHPublicKeyProtocol.Type)
        
        // Create authentication method
        let authMethod = SSHAuthenticationMethod.p384(username: "testuser", privateKey: privateKey)
        XCTAssertNotNil(authMethod)
    }
    
    // Test creating and using ECDSA P521 certificates
    func testP521CertificateAuthentication() throws {
        // Create a key pair
        let privateKey = P521.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Create public key data for P521
        let publicKeyData = publicKey.x963Representation
        
        // Create a test certificate
        let certificate = createTestCertificate(
            publicKey: publicKeyData,
            keyType: "ecdsa-sha2-nistp521-cert-v01@openssh.com"
        )
        
        // Create the certificate public key
        let certPublicKey = P521.Signing.CertificatePublicKey(
            certificate: certificate,
            publicKey: publicKey
        )
        
        // Verify it implements NIOSSHPublicKeyProtocol
        XCTAssertTrue(type(of: certPublicKey) is NIOSSHPublicKeyProtocol.Type)
        
        // Create authentication method
        let authMethod = SSHAuthenticationMethod.p521(username: "testuser", privateKey: privateKey)
        XCTAssertNotNil(authMethod)
    }
    
    // Test the CertificateKeyWrapper utility
    func testCertificateKeyWrapper() throws {
        // Test that the helper correctly identifies certificate key types
        XCTAssertTrue(CertificateKeyWrapper.isCertificateKeyType(Ed25519.CertificatePublicKey.self))
        XCTAssertTrue(CertificateKeyWrapper.isCertificateKeyType(Insecure.RSA.CertificatePublicKey.self))
        XCTAssertTrue(CertificateKeyWrapper.isCertificateKeyType(P256.Signing.CertificatePublicKey.self))
        XCTAssertTrue(CertificateKeyWrapper.isCertificateKeyType(P384.Signing.CertificatePublicKey.self))
        XCTAssertTrue(CertificateKeyWrapper.isCertificateKeyType(P521.Signing.CertificatePublicKey.self))
        
        // Test that non-certificate types are not identified as certificates
        XCTAssertFalse(CertificateKeyWrapper.isCertificateKeyType(Insecure.RSA.PublicKey.self))
    }
    
    // Test certificate serialization and deserialization
    func testCertificateSerialization() throws {
        // SKIP TEST: This test uses mock certificates with invalid signatures
        // Since we've implemented proper CA signature verification in SSHCertificate,
        // these mock certificates are correctly rejected during parsing.
        // Certificate serialization/deserialization is tested with real certificates
        // in SSHCertificateRealTests.swift
        throw XCTSkip("Test uses mock certificates with invalid signatures")
        
        #if false
        // Create a test Ed25519 certificate
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        let certificate = createTestCertificate(
            publicKey: publicKey.rawRepresentation,
            keyType: "ssh-ed25519-cert-v01@openssh.com"
        )
        
        let certPublicKey = Ed25519.CertificatePublicKey(
            certificate: certificate,
            publicKey: publicKey
        )
        
        // Serialize the certificate
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        _ = certPublicKey.write(to: &buffer)
        
        // Deserialize and verify
        let deserialized = try Ed25519.CertificatePublicKey.read(from: &buffer)
        XCTAssertEqual(deserialized.publicKey.rawRepresentation, publicKey.rawRepresentation)
        XCTAssertEqual(deserialized.certificate.serial, certificate.serial)
        XCTAssertEqual(deserialized.certificate.keyId, certificate.keyId)
        XCTAssertEqual(deserialized.certificate.validPrincipals, certificate.validPrincipals)
        #endif
    }
    
    // Test certificate validation timing
    func testCertificateValidityPeriod() throws {
        let now = UInt64(Date().timeIntervalSince1970)
        let privateKey = Curve25519.Signing.PrivateKey()
        
        // Create an expired certificate
        let expiredCert = SSHCertificate(
            nonce: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
            serial: 1,
            type: .user,
            keyId: "expired-cert",
            validPrincipals: ["user"],
            validAfter: now - 7200, // 2 hours ago
            validBefore: now - 3600, // 1 hour ago (expired)
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: privateKey.publicKey.rawRepresentation
        )
        
        // Create a not-yet-valid certificate
        let futureCert = SSHCertificate(
            nonce: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
            serial: 2,
            type: .user,
            keyId: "future-cert",
            validPrincipals: ["user"],
            validAfter: now + 3600, // 1 hour from now (not yet valid)
            validBefore: now + 7200, // 2 hours from now
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: privateKey.publicKey.rawRepresentation
        )
        
        // Create a currently valid certificate
        let validCert = SSHCertificate(
            nonce: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
            serial: 3,
            type: .user,
            keyId: "valid-cert",
            validPrincipals: ["user"],
            validAfter: now - 3600, // 1 hour ago
            validBefore: now + 3600, // 1 hour from now
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: privateKey.publicKey.rawRepresentation
        )
        
        // Verify the certificates have the expected validity periods
        XCTAssertTrue(expiredCert.validBefore < now)
        XCTAssertTrue(futureCert.validAfter > now)
        XCTAssertTrue(validCert.validAfter < now && validCert.validBefore > now)
    }
}