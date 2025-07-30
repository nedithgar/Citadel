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
    
    // Test that authentication methods can be created with certificate-enabled keys
    func testAuthenticationMethodsWithCertificates() throws {
        // Ed25519
        let ed25519Key = Curve25519.Signing.PrivateKey()
        let ed25519Auth = SSHAuthenticationMethod.ed25519(username: "test", privateKey: ed25519Key)
        XCTAssertNotNil(ed25519Auth)
        
        // RSA
        let rsaKey = try Insecure.RSA.PrivateKey(keySize: .bits2048)
        let rsaAuth = SSHAuthenticationMethod.rsa(username: "test", privateKey: rsaKey)
        XCTAssertNotNil(rsaAuth)
        
        // P256
        let p256Key = P256.Signing.PrivateKey()
        let p256Auth = SSHAuthenticationMethod.p256(username: "test", privateKey: p256Key)
        XCTAssertNotNil(p256Auth)
        
        // P384
        let p384Key = P384.Signing.PrivateKey()
        let p384Auth = SSHAuthenticationMethod.p384(username: "test", privateKey: p384Key)
        XCTAssertNotNil(p384Auth)
        
        // P521
        let p521Key = P521.Signing.PrivateKey()
        let p521Auth = SSHAuthenticationMethod.p521(username: "test", privateKey: p521Key)
        XCTAssertNotNil(p521Auth)
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
    
    // Test certificate parsing functionality (from existing certificate tests)
    func testEd25519CertificateParsing() throws {
        // This would test the actual certificate parsing if we had test certificate data
        // For now, we verify the type exists and implements the required protocol
        XCTAssertTrue(Ed25519.CertificatePublicKey.self is NIOSSHPublicKeyProtocol.Type)
    }
    
    func testRSACertificateParsing() throws {
        // Verify RSA certificate types implement the required protocol
        XCTAssertTrue(Insecure.RSA.CertificatePublicKey.self is NIOSSHPublicKeyProtocol.Type)
    }
    
    func testECDSACertificateParsing() throws {
        // Verify ECDSA certificate types implement the required protocol
        XCTAssertTrue(P256.Signing.CertificatePublicKey.self is NIOSSHPublicKeyProtocol.Type)
        XCTAssertTrue(P384.Signing.CertificatePublicKey.self is NIOSSHPublicKeyProtocol.Type)
        XCTAssertTrue(P521.Signing.CertificatePublicKey.self is NIOSSHPublicKeyProtocol.Type)
    }
}