import Foundation
import NIOSSH
import NIO
import Crypto

/// A specialized builder for creating ECDSA certificates in the format expected by NIOSSH.
/// This builder creates certificates with the public key in SSH wire format within the certificate data.
public enum ECDSACertificateBuilder {
    
    /// Builds a P256 certificate in NIOSSH-compatible format
    public static func buildP256Certificate(
        from certificate: P256.Signing.CertificatePublicKey
    ) -> Data? {
        var buffer = ByteBufferAllocator().buffer(capacity: 4096)
        
        // Write key type
        buffer.writeSSHString("ecdsa-sha2-nistp256-cert-v01@openssh.com")
        
        // Write nonce (use existing nonce if available)
        let nonce = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        buffer.writeSSHString(nonce)
        
        // Write curve identifier
        buffer.writeSSHString("nistp256")
        
        // Write EC point as raw data
        buffer.writeSSHString(certificate.publicKey.x963Representation)
        
        // Write certificate fields
        buffer.writeInteger(certificate.certificate.serial)
        buffer.writeInteger(certificate.certificate.type)
        buffer.writeSSHString(certificate.certificate.keyId)
        
        // Write valid principals
        var principalsBuffer = ByteBufferAllocator().buffer(capacity: 512)
        for principal in certificate.certificate.validPrincipals {
            principalsBuffer.writeSSHString(principal)
        }
        buffer.writeSSHString(Data(principalsBuffer.readableBytesView))
        
        // Write validity period
        buffer.writeInteger(certificate.certificate.validAfter)
        buffer.writeInteger(certificate.certificate.validBefore)
        
        // Write critical options
        var criticalOptionsBuffer = ByteBufferAllocator().buffer(capacity: 512)
        for (name, value) in certificate.certificate.criticalOptions {
            criticalOptionsBuffer.writeSSHString(name)
            criticalOptionsBuffer.writeSSHString(value)
        }
        buffer.writeSSHString(Data(criticalOptionsBuffer.readableBytesView))
        
        // Write extensions
        var extensionsBuffer = ByteBufferAllocator().buffer(capacity: 512)
        for (name, value) in certificate.certificate.extensions {
            extensionsBuffer.writeSSHString(name)
            extensionsBuffer.writeSSHString(value)
        }
        buffer.writeSSHString(Data(extensionsBuffer.readableBytesView))
        
        // Write reserved
        buffer.writeSSHString(certificate.certificate.reserved)
        
        // Write signature key
        buffer.writeSSHString(certificate.certificate.signatureKey)
        
        // Write signature
        buffer.writeSSHString(certificate.certificate.signature)
        
        return Data(buffer.readableBytesView)
    }
    
    /// Builds a P384 certificate in NIOSSH-compatible format
    public static func buildP384Certificate(
        from certificate: P384.Signing.CertificatePublicKey
    ) -> Data? {
        var buffer = ByteBufferAllocator().buffer(capacity: 4096)
        
        // Write key type
        buffer.writeSSHString("ecdsa-sha2-nistp384-cert-v01@openssh.com")
        
        // Write nonce
        let nonce = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        buffer.writeSSHString(nonce)
        
        // Write curve identifier
        buffer.writeSSHString("nistp384")
        
        // Write EC point as raw data
        buffer.writeSSHString(certificate.publicKey.x963Representation)
        
        // Write certificate fields
        buffer.writeInteger(certificate.certificate.serial)
        buffer.writeInteger(certificate.certificate.type)
        buffer.writeSSHString(certificate.certificate.keyId)
        
        // Write valid principals
        var principalsBuffer = ByteBufferAllocator().buffer(capacity: 512)
        for principal in certificate.certificate.validPrincipals {
            principalsBuffer.writeSSHString(principal)
        }
        buffer.writeSSHString(Data(principalsBuffer.readableBytesView))
        
        // Write validity period
        buffer.writeInteger(certificate.certificate.validAfter)
        buffer.writeInteger(certificate.certificate.validBefore)
        
        // Write critical options
        var criticalOptionsBuffer = ByteBufferAllocator().buffer(capacity: 512)
        for (name, value) in certificate.certificate.criticalOptions {
            criticalOptionsBuffer.writeSSHString(name)
            criticalOptionsBuffer.writeSSHString(value)
        }
        buffer.writeSSHString(Data(criticalOptionsBuffer.readableBytesView))
        
        // Write extensions
        var extensionsBuffer = ByteBufferAllocator().buffer(capacity: 512)
        for (name, value) in certificate.certificate.extensions {
            extensionsBuffer.writeSSHString(name)
            extensionsBuffer.writeSSHString(value)
        }
        buffer.writeSSHString(Data(extensionsBuffer.readableBytesView))
        
        // Write reserved
        buffer.writeSSHString(certificate.certificate.reserved)
        
        // Write signature key
        buffer.writeSSHString(certificate.certificate.signatureKey)
        
        // Write signature
        buffer.writeSSHString(certificate.certificate.signature)
        
        return Data(buffer.readableBytesView)
    }
    
    /// Builds a P521 certificate in NIOSSH-compatible format
    public static func buildP521Certificate(
        from certificate: P521.Signing.CertificatePublicKey
    ) -> Data? {
        var buffer = ByteBufferAllocator().buffer(capacity: 4096)
        
        // Write key type
        buffer.writeSSHString("ecdsa-sha2-nistp521-cert-v01@openssh.com")
        
        // Write nonce
        let nonce = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        buffer.writeSSHString(nonce)
        
        // Write curve identifier
        buffer.writeSSHString("nistp521")
        
        // Write EC point as raw data
        buffer.writeSSHString(certificate.publicKey.x963Representation)
        
        // Write certificate fields
        buffer.writeInteger(certificate.certificate.serial)
        buffer.writeInteger(certificate.certificate.type)
        buffer.writeSSHString(certificate.certificate.keyId)
        
        // Write valid principals
        var principalsBuffer = ByteBufferAllocator().buffer(capacity: 512)
        for principal in certificate.certificate.validPrincipals {
            principalsBuffer.writeSSHString(principal)
        }
        buffer.writeSSHString(Data(principalsBuffer.readableBytesView))
        
        // Write validity period
        buffer.writeInteger(certificate.certificate.validAfter)
        buffer.writeInteger(certificate.certificate.validBefore)
        
        // Write critical options
        var criticalOptionsBuffer = ByteBufferAllocator().buffer(capacity: 512)
        for (name, value) in certificate.certificate.criticalOptions {
            criticalOptionsBuffer.writeSSHString(name)
            criticalOptionsBuffer.writeSSHString(value)
        }
        buffer.writeSSHString(Data(criticalOptionsBuffer.readableBytesView))
        
        // Write extensions
        var extensionsBuffer = ByteBufferAllocator().buffer(capacity: 512)
        for (name, value) in certificate.certificate.extensions {
            extensionsBuffer.writeSSHString(name)
            extensionsBuffer.writeSSHString(value)
        }
        buffer.writeSSHString(Data(extensionsBuffer.readableBytesView))
        
        // Write reserved
        buffer.writeSSHString(certificate.certificate.reserved)
        
        // Write signature key
        buffer.writeSSHString(certificate.certificate.signatureKey)
        
        // Write signature
        buffer.writeSSHString(certificate.certificate.signature)
        
        return Data(buffer.readableBytesView)
    }
}