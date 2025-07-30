import XCTest
import Crypto
import _CryptoExtras
import NIO
@testable import Citadel
import NIOSSH

final class ECDSACertificateTests: XCTestCase {
    
    // MARK: - P256 Certificate Tests
    
    func testP256CertificateParsing() throws {
        // Create a mock certificate data structure
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        
        // Write key type
        buffer.writeSSHString("ecdsa-sha2-nistp256-cert-v01@openssh.com")
        
        // Write nonce (32 random bytes)
        let nonce = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        buffer.writeSSHString(nonce)
        
        // Generate a test P256 key pair
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Write public key components (curve identifier and point data)
        buffer.writeSSHString("nistp256")
        buffer.writeSSHString(publicKey.x963Representation)
        
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
        
        // Write CA public key (using another P256 key as CA)
        let caPrivateKey = P256.Signing.PrivateKey()
        let caPublicKey = caPrivateKey.publicKey
        var caKeyBuffer = ByteBufferAllocator().buffer(capacity: 256)
        caKeyBuffer.writeSSHString("ecdsa-sha2-nistp256")
        caKeyBuffer.writeSSHString("nistp256")
        caKeyBuffer.writeSSHString(caPublicKey.x963Representation)
        buffer.writeSSHString(Data(caKeyBuffer.readableBytesView))
        
        // Create signature (mock - in real implementation, this would be signed by CA)
        let signatureData = Data("mock-signature".utf8)
        buffer.writeSSHString(signatureData)
        
        // Parse the certificate
        let certificateData = Data(buffer.readableBytesView)
        let certificate = try P256.Signing.CertificatePublicKey(certificateData: certificateData)
        
        // Verify parsed data
        XCTAssertEqual(certificate.certificate.serial, 12345)
        XCTAssertEqual(certificate.certificate.type, 1)
        XCTAssertEqual(certificate.certificate.keyId, "test-key-id")
        XCTAssertEqual(certificate.certificate.validPrincipals, ["user1", "user2"])
        XCTAssertEqual(certificate.certificate.validAfter, 0)
        XCTAssertGreaterThan(certificate.certificate.validBefore, UInt64(Date().timeIntervalSince1970))
        XCTAssertEqual(certificate.certificate.extensions.count, 2)
        XCTAssertEqual(certificate.publicKey.x963Representation, publicKey.x963Representation)
    }
    
    func testP256CertificateSerialization() throws {
        // Create a certificate
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        let certificate = SSHCertificate(
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
            publicKey: publicKey.x963Representation
        )
        
        let certPublicKey = P256.Signing.CertificatePublicKey(certificate: certificate, publicKey: publicKey)
        
        // Serialize
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        let written = certPublicKey.write(to: &buffer)
        XCTAssertGreaterThan(written, 0)
        
        // Verify key type is written correctly
        buffer.moveReaderIndex(to: 0)
        let keyType = buffer.readSSHString()
        XCTAssertEqual(keyType, "ecdsa-sha2-nistp256-cert-v01@openssh.com")
    }
    
    func testP256CertificateEquality() throws {
        let privateKey1 = P256.Signing.PrivateKey()
        let publicKey1 = privateKey1.publicKey
        
        let privateKey2 = P256.Signing.PrivateKey()
        let publicKey2 = privateKey2.publicKey
        
        let certificate1 = SSHCertificate(
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
            publicKey: publicKey1.x963Representation
        )
        
        let certificate2 = SSHCertificate(
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
            publicKey: publicKey1.x963Representation
        )
        
        let certificate3 = SSHCertificate(
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
            publicKey: publicKey2.x963Representation
        )
        
        let certKey1 = P256.Signing.CertificatePublicKey(certificate: certificate1, publicKey: publicKey1)
        let certKey2 = P256.Signing.CertificatePublicKey(certificate: certificate2, publicKey: publicKey1)
        let certKey3 = P256.Signing.CertificatePublicKey(certificate: certificate3, publicKey: publicKey2)
        
        // Same public key and serial
        XCTAssertTrue(certKey1 == certKey2)
        
        // Different public key or serial
        XCTAssertFalse(certKey1 == certKey3)
    }
    
    // MARK: - P384 Certificate Tests
    
    func testP384CertificateParsing() throws {
        // Create a mock certificate data structure
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        
        // Write key type
        buffer.writeSSHString("ecdsa-sha2-nistp384-cert-v01@openssh.com")
        
        // Write nonce (32 random bytes)
        let nonce = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        buffer.writeSSHString(nonce)
        
        // Generate a test P384 key pair
        let privateKey = P384.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Write public key components (curve identifier and point data)
        buffer.writeSSHString("nistp384")
        buffer.writeSSHString(publicKey.x963Representation)
        
        // Write certificate fields
        buffer.writeInteger(UInt64(67890)) // serial
        buffer.writeInteger(UInt32(2)) // type (host)
        buffer.writeSSHString("test-host-key") // key ID
        
        // Write valid principals
        var principalsBuffer = ByteBufferAllocator().buffer(capacity: 256)
        principalsBuffer.writeSSHString("host.example.com")
        buffer.writeSSHString(Data(principalsBuffer.readableBytesView))
        
        // Write validity period
        buffer.writeInteger(UInt64(0)) // valid after (epoch)
        buffer.writeInteger(UInt64(Date().timeIntervalSince1970 + 7200)) // valid before (2 hours from now)
        
        // Write critical options (empty)
        buffer.writeSSHString(Data())
        
        // Write extensions (empty)
        buffer.writeSSHString(Data())
        
        // Write reserved
        buffer.writeSSHString(Data())
        
        // Write CA public key (using another P384 key as CA)
        let caPrivateKey = P384.Signing.PrivateKey()
        let caPublicKey = caPrivateKey.publicKey
        var caKeyBuffer = ByteBufferAllocator().buffer(capacity: 256)
        caKeyBuffer.writeSSHString("ecdsa-sha2-nistp384")
        caKeyBuffer.writeSSHString("nistp384")
        caKeyBuffer.writeSSHString(caPublicKey.x963Representation)
        buffer.writeSSHString(Data(caKeyBuffer.readableBytesView))
        
        // Create signature (mock - in real implementation, this would be signed by CA)
        let signatureData = Data("mock-signature-384".utf8)
        buffer.writeSSHString(signatureData)
        
        // Parse the certificate
        let certificateData = Data(buffer.readableBytesView)
        let certificate = try P384.Signing.CertificatePublicKey(certificateData: certificateData)
        
        // Verify parsed data
        XCTAssertEqual(certificate.certificate.serial, 67890)
        XCTAssertEqual(certificate.certificate.type, 2)
        XCTAssertEqual(certificate.certificate.keyId, "test-host-key")
        XCTAssertEqual(certificate.certificate.validPrincipals, ["host.example.com"])
        XCTAssertEqual(certificate.certificate.validAfter, 0)
        XCTAssertGreaterThan(certificate.certificate.validBefore, UInt64(Date().timeIntervalSince1970))
        XCTAssertEqual(certificate.publicKey.x963Representation, publicKey.x963Representation)
    }
    
    // MARK: - P521 Certificate Tests
    
    func testP521CertificateParsing() throws {
        // Create a mock certificate data structure
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        
        // Write key type
        buffer.writeSSHString("ecdsa-sha2-nistp521-cert-v01@openssh.com")
        
        // Write nonce (32 random bytes)
        let nonce = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        buffer.writeSSHString(nonce)
        
        // Generate a test P521 key pair
        let privateKey = P521.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Write public key components (curve identifier and point data)
        buffer.writeSSHString("nistp521")
        buffer.writeSSHString(publicKey.x963Representation)
        
        // Write certificate fields
        buffer.writeInteger(UInt64(11111)) // serial
        buffer.writeInteger(UInt32(1)) // type (user)
        buffer.writeSSHString("test-p521-key") // key ID
        
        // Write valid principals
        var principalsBuffer = ByteBufferAllocator().buffer(capacity: 256)
        principalsBuffer.writeSSHString("admin")
        principalsBuffer.writeSSHString("root")
        buffer.writeSSHString(Data(principalsBuffer.readableBytesView))
        
        // Write validity period
        buffer.writeInteger(UInt64(Date().timeIntervalSince1970 - 3600)) // valid from 1 hour ago
        buffer.writeInteger(UInt64(Date().timeIntervalSince1970 + 3600)) // valid until 1 hour from now
        
        // Write critical options
        var criticalOptionsBuffer = ByteBufferAllocator().buffer(capacity: 256)
        criticalOptionsBuffer.writeSSHString("source-address")
        criticalOptionsBuffer.writeSSHString(Data("192.168.1.0/24".utf8))
        buffer.writeSSHString(Data(criticalOptionsBuffer.readableBytesView))
        
        // Write extensions
        var extensionsBuffer = ByteBufferAllocator().buffer(capacity: 256)
        extensionsBuffer.writeSSHString("permit-pty")
        extensionsBuffer.writeSSHString(Data())
        buffer.writeSSHString(Data(extensionsBuffer.readableBytesView))
        
        // Write reserved
        buffer.writeSSHString(Data())
        
        // Write CA public key (using another P521 key as CA)
        let caPrivateKey = P521.Signing.PrivateKey()
        let caPublicKey = caPrivateKey.publicKey
        var caKeyBuffer = ByteBufferAllocator().buffer(capacity: 256)
        caKeyBuffer.writeSSHString("ecdsa-sha2-nistp521")
        caKeyBuffer.writeSSHString("nistp521")
        caKeyBuffer.writeSSHString(caPublicKey.x963Representation)
        buffer.writeSSHString(Data(caKeyBuffer.readableBytesView))
        
        // Create signature (mock - in real implementation, this would be signed by CA)
        let signatureData = Data("mock-signature-521".utf8)
        buffer.writeSSHString(signatureData)
        
        // Parse the certificate
        let certificateData = Data(buffer.readableBytesView)
        let certificate = try P521.Signing.CertificatePublicKey(certificateData: certificateData)
        
        // Verify parsed data
        XCTAssertEqual(certificate.certificate.serial, 11111)
        XCTAssertEqual(certificate.certificate.type, 1)
        XCTAssertEqual(certificate.certificate.keyId, "test-p521-key")
        XCTAssertEqual(certificate.certificate.validPrincipals, ["admin", "root"])
        XCTAssertEqual(certificate.certificate.criticalOptions.count, 1)
        XCTAssertEqual(certificate.certificate.extensions.count, 1)
        XCTAssertEqual(certificate.publicKey.x963Representation, publicKey.x963Representation)
    }
    
    // MARK: - Invalid Certificate Tests
    
    func testInvalidP256CertificateParsing() throws {
        // Test with invalid key type
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHString("ssh-rsa") // Wrong key type
        
        let data = Data(buffer.readableBytesView)
        XCTAssertThrowsError(try P256.Signing.CertificatePublicKey(certificateData: data)) { error in
            XCTAssertTrue(error is SSHCertificateError)
        }
        
        // Test with missing fields
        buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHString("ecdsa-sha2-nistp256-cert-v01@openssh.com")
        buffer.writeSSHString(Data((0..<32).map { _ in UInt8.random(in: 0...255) })) // nonce
        // Missing public key and other fields
        
        let incompleteData = Data(buffer.readableBytesView)
        XCTAssertThrowsError(try P256.Signing.CertificatePublicKey(certificateData: incompleteData)) { error in
            XCTAssertTrue(error is SSHCertificateError)
        }
    }
    
    func testWrongCurveCertificate() throws {
        // Try to parse a P384 certificate as P256
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHString("ecdsa-sha2-nistp384-cert-v01@openssh.com")
        
        let data = Data(buffer.readableBytesView)
        XCTAssertThrowsError(try P256.Signing.CertificatePublicKey(certificateData: data)) { error in
            XCTAssertTrue(error is SSHCertificateError)
        }
    }
    
    func testCertificateValidityPeriod() throws {
        let now = UInt64(Date().timeIntervalSince1970)
        let certificate = SSHCertificate(
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
    
    func testAllCurveSizes() throws {
        // Test that the public key sizes are correct for each curve
        let p256Key = P256.Signing.PrivateKey()
        let p384Key = P384.Signing.PrivateKey()
        let p521Key = P521.Signing.PrivateKey()
        
        // x963 representation includes the 0x04 prefix byte
        XCTAssertEqual(p256Key.publicKey.x963Representation.count, 65) // 1 + 2*32
        XCTAssertEqual(p384Key.publicKey.x963Representation.count, 97) // 1 + 2*48
        XCTAssertEqual(p521Key.publicKey.x963Representation.count, 133) // 1 + 2*66
    }
}