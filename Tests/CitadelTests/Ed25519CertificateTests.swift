import XCTest
import Crypto
import NIO
@testable import Citadel
import NIOSSH

final class Ed25519CertificateTests: XCTestCase {
    
    func testCertificateParsing() throws {
        // Create a mock certificate data structure
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        
        // Write key type
        buffer.writeSSHString("ssh-ed25519-cert-v01@openssh.com")
        
        // Write nonce (32 random bytes)
        let nonce = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        buffer.writeSSHString(nonce)
        
        // Generate a test Ed25519 key pair
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Write public key
        buffer.writeSSHString(publicKey.rawRepresentation)
        
        // Write certificate fields
        buffer.writeInteger(UInt64(12345)) // serial
        buffer.writeInteger(UInt32(1)) // type (user)
        buffer.writeSSHString("test-key-id") // key ID
        
        // Write valid principals
        var principalsBuffer = ByteBufferAllocator().buffer(capacity: 256)
        principalsBuffer.writeSSHString("user1")
        principalsBuffer.writeSSHString("user2")
        buffer.writeSSHString(Data(principalsBuffer.readableBytesView))
        
        // Write validity period
        buffer.writeInteger(UInt64(0)) // valid after (epoch)
        buffer.writeInteger(UInt64(Date().timeIntervalSince1970 + 3600)) // valid before (1 hour from now)
        
        // Write critical options (empty)
        buffer.writeSSHString(Data())
        
        // Write extensions
        var extensionsBuffer = ByteBufferAllocator().buffer(capacity: 256)
        extensionsBuffer.writeSSHString("permit-X11-forwarding")
        extensionsBuffer.writeSSHString(Data())
        extensionsBuffer.writeSSHString("permit-agent-forwarding")
        extensionsBuffer.writeSSHString(Data())
        buffer.writeSSHString(Data(extensionsBuffer.readableBytesView))
        
        // Write reserved
        buffer.writeSSHString(Data())
        
        // Write CA public key (using another Ed25519 key as CA)
        let caPrivateKey = Curve25519.Signing.PrivateKey()
        let caPublicKey = caPrivateKey.publicKey
        var caKeyBuffer = ByteBufferAllocator().buffer(capacity: 256)
        caKeyBuffer.writeSSHString("ssh-ed25519")
        caKeyBuffer.writeSSHString(caPublicKey.rawRepresentation)
        buffer.writeSSHString(Data(caKeyBuffer.readableBytesView))
        
        // Create signature (mock - in real implementation, this would be signed by CA)
        let signatureData = Data("mock-signature".utf8)
        buffer.writeSSHString(signatureData)
        
        // Parse the certificate
        let certificateData = Data(buffer.readableBytesView)
        let certificate = try Ed25519.CertificatePublicKey(certificateData: certificateData)
        
        // Verify parsed data
        XCTAssertEqual(certificate.certificate.serial, 12345)
        XCTAssertEqual(certificate.certificate.type, 1)
        XCTAssertEqual(certificate.certificate.keyId, "test-key-id")
        XCTAssertEqual(certificate.certificate.validPrincipals, ["user1", "user2"])
        XCTAssertEqual(certificate.certificate.validAfter, 0)
        XCTAssertGreaterThan(certificate.certificate.validBefore, UInt64(Date().timeIntervalSince1970))
        XCTAssertEqual(certificate.certificate.extensions.count, 2)
        XCTAssertEqual(certificate.publicKey.rawRepresentation, publicKey.rawRepresentation)
    }
    
    func testCertificateSerialization() throws {
        // Create a certificate
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        let certificate = SSHCertificate(
            nonce: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
            serial: 54321,
            type: 2, // host
            keyId: "host-certificate",
            validPrincipals: ["*.example.com", "example.com"],
            validAfter: 0,
            validBefore: UInt64(Date().timeIntervalSince1970 + 86400), // 24 hours
            criticalOptions: [("force-command", Data("/bin/true".utf8))],
            extensions: [("permit-pty", Data())],
            reserved: Data(),
            signatureKey: Data("ca-key-data".utf8),
            signature: Data("signature-data".utf8),
            publicKey: publicKey.rawRepresentation
        )
        
        let certPublicKey = Ed25519.CertificatePublicKey(certificate: certificate, publicKey: publicKey)
        
        // Serialize
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        let written = certPublicKey.write(to: &buffer)
        XCTAssertGreaterThan(written, 0)
        
        // Verify key type is written correctly
        buffer.moveReaderIndex(to: 0)
        let keyType = buffer.readSSHString()
        XCTAssertEqual(keyType, "ssh-ed25519-cert-v01@openssh.com")
    }
    
    func testCertificateEquality() throws {
        let privateKey1 = Curve25519.Signing.PrivateKey()
        let publicKey1 = privateKey1.publicKey
        
        let privateKey2 = Curve25519.Signing.PrivateKey()
        let publicKey2 = privateKey2.publicKey
        
        let certificate1 = SSHCertificate(
            nonce: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
            serial: 100,
            type: 1,
            keyId: "key1",
            validPrincipals: ["user1"],
            validAfter: 0,
            validBefore: 1000,
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: publicKey1.rawRepresentation
        )
        
        let certificate2 = SSHCertificate(
            nonce: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
            serial: 100,
            type: 1,
            keyId: "key1",
            validPrincipals: ["user1"],
            validAfter: 0,
            validBefore: 1000,
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: publicKey1.rawRepresentation
        )
        
        let certificate3 = SSHCertificate(
            nonce: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
            serial: 200, // Different serial
            type: 1,
            keyId: "key1",
            validPrincipals: ["user1"],
            validAfter: 0,
            validBefore: 1000,
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: publicKey2.rawRepresentation
        )
        
        let certKey1 = Ed25519.CertificatePublicKey(certificate: certificate1, publicKey: publicKey1)
        let certKey2 = Ed25519.CertificatePublicKey(certificate: certificate2, publicKey: publicKey1)
        let certKey3 = Ed25519.CertificatePublicKey(certificate: certificate3, publicKey: publicKey2)
        
        // Same public key and serial
        XCTAssertTrue(certKey1 == certKey2)
        
        // Different public key or serial
        XCTAssertFalse(certKey1 == certKey3)
    }
    
    func testInvalidCertificateParsing() throws {
        // Test with invalid key type
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHString("ssh-rsa") // Wrong key type
        
        let data = Data(buffer.readableBytesView)
        XCTAssertThrowsError(try Ed25519.CertificatePublicKey(certificateData: data)) { error in
            XCTAssertTrue(error is SSHCertificateError)
        }
        
        // Test with missing fields
        buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHString("ssh-ed25519-cert-v01@openssh.com")
        buffer.writeSSHString(Data((0..<32).map { _ in UInt8.random(in: 0...255) })) // nonce
        // Missing public key and other fields
        
        let incompleteData = Data(buffer.readableBytesView)
        XCTAssertThrowsError(try Ed25519.CertificatePublicKey(certificateData: incompleteData)) { error in
            XCTAssertTrue(error is SSHCertificateError)
        }
    }
    
    func testCertificateValidityPeriod() throws {
        let now = UInt64(Date().timeIntervalSince1970)
        let certificate = SSHCertificate(
            nonce: Data((0..<32).map { _ in UInt8.random(in: 0...255) }),
            serial: 1,
            type: 1,
            keyId: "test",
            validPrincipals: ["user"],
            validAfter: now - 3600, // Valid from 1 hour ago
            validBefore: now + 3600, // Valid until 1 hour from now
            criticalOptions: [],
            extensions: [],
            reserved: Data(),
            signatureKey: Data(),
            signature: Data(),
            publicKey: Data()
        )
        
        // The certificate should be valid now
        let currentTime = UInt64(Date().timeIntervalSince1970)
        XCTAssertLessThan(certificate.validAfter, currentTime)
        XCTAssertGreaterThan(certificate.validBefore, currentTime)
    }
    
    func testOpenSSHCompatibility() throws {
        // This tests that our implementation can parse a real OpenSSH Ed25519 certificate
        // The format follows the structure in openssh-portable-master/regress/unittests/sshkey/testdata/ed25519_1-cert.pub
        
        // Sample certificate base64 string (you would need a real one for production)
        let opensshCertString = "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIIxzuxl4z3uwAIslne8Huft+1n1IhHAlNbWZkQyyECCGAAAAIFOG6kY7Rf4UtCFvPwKgo/BztXck2xC4a2WyA34XtIwZAAAAAAAAAAgAAAACAAAABmp1bGl1cwAAABIAAAAFaG9zdDEAAAAFaG9zdDIAAAAANowB8AAAAABNHmBwAAAAAAAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACBThupGO0X+FLQhbz8CoKPwc7V3JNsQuGtlsgN+F7SMGQAAAFMAAAALc3NoLWVkMjU1MTkAAABABGTn+Bmz86Ajk+iqKCSdP5NClsYzn4alJd0V5bizhP0Kumc/HbqQfSt684J1WdSzih+EjvnTgBhK9jTBKb90AQ=="
        
        // Test that we can parse the certificate
        guard let certData = Data(base64Encoded: opensshCertString) else {
            XCTFail("Failed to decode base64 certificate")
            return
        }
        
        // Parse the certificate
        let certificate = try Ed25519.CertificatePublicKey(certificateData: certData)
        
        // Verify basic certificate properties based on the OpenSSH test data
        XCTAssertEqual(certificate.certificate.keyId, "julius")
        XCTAssertEqual(certificate.certificate.validPrincipals, ["host1", "host2"])
        XCTAssertEqual(certificate.certificate.type, 2) // SSH2_CERT_TYPE_HOST
        XCTAssertEqual(certificate.certificate.serial, 8)
        
        // Verify the embedded public key is 32 bytes (Ed25519 key size)
        XCTAssertEqual(certificate.publicKey.rawRepresentation.count, 32)
    }
}


