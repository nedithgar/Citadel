import Foundation
import Crypto
import NIO
import NIOSSH

public enum Ed25519 {
    
    // MARK: - Ed25519 Certificate Public Key Type
    
    /// Ed25519 certificate public key
    public final class CertificatePublicKey: NIOSSHPublicKeyProtocol, Equatable, Hashable {
        /// SSH certificate type identifier
        public static let publicKeyPrefix = "ssh-ed25519-cert-v01@openssh.com"
        
        /// The underlying Ed25519 public key
        public let publicKey: Curve25519.Signing.PublicKey
        
        /// The certificate data
        public let certificate: SSHCertificate
        
        /// The raw representation of the public key
        public var rawRepresentation: Data {
            publicKey.rawRepresentation
        }
        
        /// Initialize from raw certificate data
        public init(certificateData: Data) throws {
            self.certificate = try SSHCertificate(from: certificateData, expectedKeyType: Self.publicKeyPrefix)
            
            // Extract the public key from the certificate
            guard let publicKeyData = certificate.publicKey else {
                throw SSHCertificateError.missingPublicKey
            }
            
            self.publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        }
        
        /// Initialize from certificate and public key
        public init(certificate: SSHCertificate, publicKey: Curve25519.Signing.PublicKey) {
            self.certificate = certificate
            self.publicKey = publicKey
        }
        
        // MARK: - NIOSSHPublicKeyProtocol conformance
        
        public static func read(from buffer: inout ByteBuffer) throws -> CertificatePublicKey {
            // Save the entire certificate blob for later use
            let startIndex = buffer.readerIndex
            
            // Skip the key type string
            guard let keyType = buffer.readSSHString() else {
                throw SSHCertificateError.invalidCertificateType
            }
            
            guard keyType == publicKeyPrefix else {
                throw SSHCertificateError.invalidCertificateType
            }
            
            // Read the entire certificate
            buffer.moveReaderIndex(to: startIndex)
            let certificateLength = buffer.readableBytes
            guard let certificateBytes = buffer.readBytes(length: certificateLength) else {
                throw SSHCertificateError.invalidCertificateType
            }
            let certificateData = Data(certificateBytes)
            
            return try CertificatePublicKey(certificateData: certificateData)
        }
        
        public func write(to buffer: inout ByteBuffer) -> Int {
            // Serialize the entire certificate
            var certBuffer = ByteBufferAllocator().buffer(capacity: 1024)
            
            // Write key type
            certBuffer.writeSSHString(CertificatePublicKey.publicKeyPrefix)
            
            // Write nonce (32 random bytes)
            let nonce = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
            certBuffer.writeSSHData(nonce)
            
            // Write public key
            certBuffer.writeSSHData(publicKey.rawRepresentation)
            
            // Write certificate fields
            certBuffer.writeInteger(certificate.serial)
            certBuffer.writeInteger(certificate.type)
            certBuffer.writeSSHString(certificate.keyId)
            
            // Write valid principals
            var principalsBuffer = ByteBufferAllocator().buffer(capacity: 512)
            for principal in certificate.validPrincipals {
                principalsBuffer.writeSSHString(principal)
            }
            certBuffer.writeSSHString(Data(principalsBuffer.readableBytesView))
            
            // Write validity period
            certBuffer.writeInteger(certificate.validAfter)
            certBuffer.writeInteger(certificate.validBefore)
            
            // Write critical options
            var criticalOptionsBuffer = ByteBufferAllocator().buffer(capacity: 512)
            for (name, value) in certificate.criticalOptions {
                criticalOptionsBuffer.writeSSHString(name)
                criticalOptionsBuffer.writeSSHData(value)
            }
            certBuffer.writeSSHString(Data(criticalOptionsBuffer.readableBytesView))
            
            // Write extensions
            var extensionsBuffer = ByteBufferAllocator().buffer(capacity: 512)
            for (name, value) in certificate.extensions {
                extensionsBuffer.writeSSHString(name)
                extensionsBuffer.writeSSHData(value)
            }
            certBuffer.writeSSHString(Data(extensionsBuffer.readableBytesView))
            
            // Write reserved
            certBuffer.writeSSHData(certificate.reserved)
            
            // Write signature key
            certBuffer.writeSSHData(certificate.signatureKey)
            
            // Write signature
            certBuffer.writeSSHData(certificate.signature)
            
            // Write the complete certificate to the output buffer
            return buffer.writeBuffer(&certBuffer)
        }
        
        public static func == (lhs: CertificatePublicKey, rhs: CertificatePublicKey) -> Bool {
            lhs.publicKey.rawRepresentation == rhs.publicKey.rawRepresentation &&
            lhs.certificate.serial == rhs.certificate.serial
        }
        
        public func hash(into hasher: inout Hasher) {
            hasher.combine(publicKey.rawRepresentation)
            hasher.combine(certificate.serial)
        }
        
        public func isValidSignature<D: DataProtocol>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool {
            // Ed25519 certificates use the same signature validation as regular Ed25519 keys
            // The signature should be an Ed25519 signature
            let signatureBytes = signature.rawRepresentation
            
            // Parse the signature format (algorithm name + signature data)
            var signatureBuffer = ByteBuffer(data: signatureBytes)
            guard let algorithm = signatureBuffer.readSSHString(),
                  algorithm == "ssh-ed25519" else {
                return false
            }
            
            guard let signatureData = signatureBuffer.readSSHData(),
                  signatureData.count == 64 else { // Ed25519 signatures are always 64 bytes
                return false
            }
            
            // Verify using Curve25519.Signing.PublicKey
            return publicKey.isValidSignature(signatureData, for: data)
        }
    }
}

