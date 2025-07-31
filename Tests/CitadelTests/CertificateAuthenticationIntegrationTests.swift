import XCTest
@testable import Citadel
import Crypto
import _CryptoExtras
import Foundation
import NIO
import NIOSSH

final class CertificateAuthenticationIntegrationTests: XCTestCase {
    
    // Test that certificate authentication methods can be created
    func testCertificateAuthenticationMethodCreation() throws {
        // Ed25519
        let ed25519PrivateKey = Curve25519.Signing.PrivateKey()
        let ed25519Certificate = createTestEd25519Certificate(privateKey: ed25519PrivateKey)
        let ed25519Method = SSHAuthenticationMethod.ed25519Certificate(
            username: "testuser",
            privateKey: ed25519PrivateKey,
            certificate: ed25519Certificate
        )
        XCTAssertNotNil(ed25519Method)
        
        // RSA
        let rsaPrivateKey = Insecure.RSA.PrivateKey(bits: 2048)
        let rsaCertificate = createTestRSACertificate(privateKey: rsaPrivateKey)
        let rsaMethod = SSHAuthenticationMethod.rsaCertificate(
            username: "testuser",
            privateKey: rsaPrivateKey,
            certificate: rsaCertificate
        )
        XCTAssertNotNil(rsaMethod)
        
        // P256
        let p256PrivateKey = P256.Signing.PrivateKey()
        let p256Certificate = createTestP256Certificate(privateKey: p256PrivateKey)
        let p256Method = SSHAuthenticationMethod.p256Certificate(
            username: "testuser",
            privateKey: p256PrivateKey,
            certificate: p256Certificate
        )
        XCTAssertNotNil(p256Method)
        
        // P384
        let p384PrivateKey = P384.Signing.PrivateKey()
        let p384Certificate = createTestP384Certificate(privateKey: p384PrivateKey)
        let p384Method = SSHAuthenticationMethod.p384Certificate(
            username: "testuser",
            privateKey: p384PrivateKey,
            certificate: p384Certificate
        )
        XCTAssertNotNil(p384Method)
        
        // P521
        let p521PrivateKey = P521.Signing.PrivateKey()
        let p521Certificate = createTestP521Certificate(privateKey: p521PrivateKey)
        let p521Method = SSHAuthenticationMethod.p521Certificate(
            username: "testuser",
            privateKey: p521PrivateKey,
            certificate: p521Certificate
        )
        XCTAssertNotNil(p521Method)
    }
    
    // Test that CertificateAuthenticationDelegate properly handles authentication
    func testCertificateAuthenticationDirectPattern() throws {
        let eventLoop = EmbeddedEventLoop()
        defer { try! eventLoop.syncShutdownGracefully() }
        
        // Create test data
        let privateKey = Curve25519.Signing.PrivateKey()
        let certificate = createTestEd25519Certificate(privateKey: privateKey)
        
        // Create authentication method using the new direct pattern
        let authMethod = SSHAuthenticationMethod.ed25519Certificate(
            username: "testuser",
            privateKey: privateKey,
            certificate: certificate
        )
        
        // Test with publicKey method available
        let availableMethods = NIOSSHAvailableUserAuthenticationMethods.publicKey
        let promise = eventLoop.makePromise(of: NIOSSHUserAuthenticationOffer?.self)
        
        authMethod.nextAuthenticationType(
            availableMethods: availableMethods,
            nextChallengePromise: promise
        )
        
        // Verify the offer was created correctly
        let offer = try promise.futureResult.wait()
        XCTAssertNotNil(offer)
        XCTAssertEqual(offer?.username, "testuser")
        
        // Test without publicKey method available
        let noPublicKeyMethods = NIOSSHAvailableUserAuthenticationMethods.password
        let failPromise = eventLoop.makePromise(of: NIOSSHUserAuthenticationOffer?.self)
        
        // Create a new auth method since the previous one has consumed its implementations
        let authMethodCopy = SSHAuthenticationMethod.ed25519Certificate(
            username: "testuser",
            privateKey: privateKey,
            certificate: certificate
        )
        
        authMethodCopy.nextAuthenticationType(
            availableMethods: noPublicKeyMethods,
            nextChallengePromise: failPromise
        )
        
        // Verify it fails appropriately
        XCTAssertThrowsError(try failPromise.futureResult.wait()) { error in
            XCTAssertTrue(error is SSHClientError)
        }
    }
    
    // Test certificate conversion to NIOSSH types
    func testCertificateConversion() throws {
        // Test Ed25519 certificate conversion
        let ed25519PrivateKey = Curve25519.Signing.PrivateKey()
        let ed25519Certificate = createTestEd25519Certificate(privateKey: ed25519PrivateKey)
        
        let ed25519PublicKey = CertificateConverter.convertToNIOSSHPublicKey(ed25519Certificate)
        XCTAssertNotNil(ed25519PublicKey)
        
        let ed25519CertifiedKey = CertificateConverter.convertToNIOSSHCertifiedPublicKey(ed25519Certificate)
        XCTAssertNotNil(ed25519CertifiedKey)
        
        // Test RSA certificate conversion - NIOSSH doesn't support RSA certificates
        let rsaPrivateKey = Insecure.RSA.PrivateKey(bits: 2048)
        let rsaCertificate = createTestRSACertificate(privateKey: rsaPrivateKey)
        
        let rsaPublicKey = CertificateConverter.convertToNIOSSHPublicKey(rsaCertificate)
        XCTAssertNil(rsaPublicKey, "RSA certificate conversion should fail as NIOSSH doesn't support RSA certificates")
        
        let rsaCertifiedKey = CertificateConverter.convertToNIOSSHCertifiedPublicKey(rsaCertificate)
        XCTAssertNil(rsaCertifiedKey, "RSA certificate conversion should fail as NIOSSH doesn't support RSA certificates")
        
        // Test P256 certificate conversion
        let p256PrivateKey = P256.Signing.PrivateKey()
        let p256Certificate = createTestP256Certificate(privateKey: p256PrivateKey)
        
        let p256PublicKey = CertificateConverter.convertToNIOSSHPublicKey(p256Certificate)
        XCTAssertNotNil(p256PublicKey)
        
        let p256CertifiedKey = CertificateConverter.convertToNIOSSHCertifiedPublicKey(p256Certificate)
        XCTAssertNotNil(p256CertifiedKey)
    }
    
    // Helper functions to create test certificates
    
    private func createTestCertificate(publicKey: Data, keyType: String) -> SSHCertificate {
        let now = UInt64(Date().timeIntervalSince1970)
        let caPrivateKey = Curve25519.Signing.PrivateKey()
        let caPublicKey = caPrivateKey.publicKey
        
        // Create CA signature key data
        var caKeyBuffer = ByteBufferAllocator().buffer(capacity: 256)
        caKeyBuffer.writeSSHString("ssh-ed25519")
        caKeyBuffer.writeSSHData(caPublicKey.rawRepresentation)
        let caKeyData = Data(caKeyBuffer.readableBytesView)
        
        // Create a dummy signature
        var signatureBuffer = ByteBufferAllocator().buffer(capacity: 128)
        signatureBuffer.writeSSHString("ssh-ed25519")
        signatureBuffer.writeSSHData(Data(repeating: 0, count: 64))
        let signatureData = Data(signatureBuffer.readableBytesView)
        
        return SSHCertificate(
            nonce: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
            serial: 1,
            type: 1, // User certificate
            keyId: "test-user@example.com",
            validPrincipals: ["testuser"],
            validAfter: now - 3600,
            validBefore: now + 3600,
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
    
    private func createTestEd25519Certificate(privateKey: Curve25519.Signing.PrivateKey) -> Ed25519.CertificatePublicKey {
        let publicKey = privateKey.publicKey
        let certificate = createTestCertificate(
            publicKey: publicKey.rawRepresentation,
            keyType: "ssh-ed25519-cert-v01@openssh.com"
        )
        return Ed25519.CertificatePublicKey(
            certificate: certificate,
            publicKey: publicKey
        )
    }
    
    private func createTestRSACertificate(privateKey: Insecure.RSA.PrivateKey) -> Insecure.RSA.CertificatePublicKey {
        let publicKey = privateKey.publicKey as! Insecure.RSA.PublicKey
        let certificate = createTestCertificate(
            publicKey: publicKey.rawRepresentation,
            keyType: "ssh-rsa-cert-v01@openssh.com"
        )
        return Insecure.RSA.CertificatePublicKey(
            certificate: certificate,
            publicKey: publicKey,
            algorithm: .sha256Cert
        )
    }
    
    private func createTestP256Certificate(privateKey: P256.Signing.PrivateKey) -> P256.Signing.CertificatePublicKey {
        let publicKey = privateKey.publicKey
        let certificate = createTestCertificate(
            publicKey: publicKey.x963Representation,
            keyType: "ecdsa-sha2-nistp256-cert-v01@openssh.com"
        )
        return P256.Signing.CertificatePublicKey(
            certificate: certificate,
            publicKey: publicKey
        )
    }
    
    private func createTestP384Certificate(privateKey: P384.Signing.PrivateKey) -> P384.Signing.CertificatePublicKey {
        let publicKey = privateKey.publicKey
        let certificate = createTestCertificate(
            publicKey: publicKey.x963Representation,
            keyType: "ecdsa-sha2-nistp384-cert-v01@openssh.com"
        )
        return P384.Signing.CertificatePublicKey(
            certificate: certificate,
            publicKey: publicKey
        )
    }
    
    private func createTestP521Certificate(privateKey: P521.Signing.PrivateKey) -> P521.Signing.CertificatePublicKey {
        let publicKey = privateKey.publicKey
        let certificate = createTestCertificate(
            publicKey: publicKey.x963Representation,
            keyType: "ecdsa-sha2-nistp521-cert-v01@openssh.com"
        )
        return P521.Signing.CertificatePublicKey(
            certificate: certificate,
            publicKey: publicKey
        )
    }
}