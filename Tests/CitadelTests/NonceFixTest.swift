import XCTest
import Crypto
import NIO
@testable import Citadel

final class NonceFixTest: XCTestCase {
    
    func testNonceIsReadAsFirstFieldAfterKeyType() throws {
        // Create a test certificate with known nonce value
        let nonce = Data(repeating: 0xAB, count: 32)
        let serial: UInt64 = 12345
        let keyId = "test-key"
        let validPrincipals = ["testuser"]
        let validAfter: UInt64 = 0
        let validBefore: UInt64 = UInt64.max
        let reserved = Data()
        
        // Create a dummy CA key (Ed25519)
        let caPrivateKey = Curve25519.Signing.PrivateKey()
        let caPublicKey = caPrivateKey.publicKey
        
        // Create CA key blob
        var caKeyBuffer = ByteBufferAllocator().buffer(capacity: 128)
        caKeyBuffer.writeSSHString("ssh-ed25519")
        caKeyBuffer.writeSSHData(caPublicKey.rawRepresentation)
        let signatureKey = Data(caKeyBuffer.readableBytesView)
        
        // Create a test Ed25519 public key for the certificate
        let testPrivateKey = Curve25519.Signing.PrivateKey()
        let testPublicKey = testPrivateKey.publicKey
        
        // Build the certificate blob following OpenSSH format
        var certBuffer = ByteBufferAllocator().buffer(capacity: 1024)
        
        // Write key type
        certBuffer.writeSSHString("ssh-ed25519-cert-v01@openssh.com")
        
        // Write nonce as FIRST field after key type (OpenSSH format)
        certBuffer.writeSSHData(nonce)
        
        // Write public key
        certBuffer.writeSSHData(testPublicKey.rawRepresentation)
        
        // Write certificate fields
        certBuffer.writeInteger(serial)
        certBuffer.writeInteger(UInt32(1)) // user certificate
        certBuffer.writeSSHString(keyId)
        
        // Write valid principals
        var principalsBuffer = ByteBufferAllocator().buffer(capacity: 512)
        for principal in validPrincipals {
            principalsBuffer.writeSSHString(principal)
        }
        certBuffer.writeSSHString(Data(principalsBuffer.readableBytesView))
        
        // Write validity period
        certBuffer.writeInteger(validAfter)
        certBuffer.writeInteger(validBefore)
        
        // Write critical options (empty)
        certBuffer.writeSSHString(Data())
        
        // Write extensions (empty) 
        certBuffer.writeSSHString(Data())
        
        // Write reserved
        certBuffer.writeSSHData(reserved)
        
        // Write signature key
        certBuffer.writeSSHData(signatureKey)
        
        // Create signature over everything so far
        let dataToSign = Data(certBuffer.readableBytesView)
        let signature = try caPrivateKey.signature(for: dataToSign)
        
        // Write signature
        var sigBuffer = ByteBufferAllocator().buffer(capacity: 128)
        sigBuffer.writeSSHString("ssh-ed25519")
        sigBuffer.writeSSHData(signature)
        certBuffer.writeSSHData(Data(sigBuffer.readableBytesView))
        
        // Now parse the certificate
        let certData = Data(certBuffer.readableBytesView)
        let parsedCert = try SSHCertificate(from: certData, expectedKeyType: "ssh-ed25519-cert-v01@openssh.com")
        
        // Verify the nonce was parsed correctly
        XCTAssertEqual(parsedCert.nonce, nonce, "Nonce should be parsed as first field after key type")
        
        // Verify other fields to ensure parsing continues correctly
        XCTAssertEqual(parsedCert.serial, serial)
        XCTAssertEqual(parsedCert.keyId, keyId)
        XCTAssertEqual(parsedCert.validPrincipals, validPrincipals)
        XCTAssertEqual(parsedCert.validAfter, validAfter)
        XCTAssertEqual(parsedCert.validBefore, validBefore)
        
        // Verify public key was parsed correctly
        XCTAssertEqual(parsedCert.publicKey, testPublicKey.rawRepresentation)
    }
}

// Extension to help with buffer operations
extension ByteBuffer {
    @discardableResult
    mutating func writeSSHData(_ data: Data) -> Int {
        let written = writeInteger(UInt32(data.count))
        return written + writeBytes(data)
    }
}