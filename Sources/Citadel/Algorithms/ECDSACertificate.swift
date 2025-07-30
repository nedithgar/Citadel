import Foundation
import Crypto
import _CryptoExtras
import NIO
import NIOSSH

// MARK: - P256 Certificate Support

extension P256.Signing {
    /// P256 certificate public key
    public final class CertificatePublicKey: NIOSSHPublicKeyProtocol, Equatable, Hashable {
        /// SSH certificate type identifier
        public static let publicKeyPrefix = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
        
        /// The underlying P256 public key
        public let publicKey: P256.Signing.PublicKey
        
        /// The certificate data
        public let certificate: SSHCertificate
        
        /// The raw representation of the public key
        public var rawRepresentation: Data {
            publicKey.x963Representation
        }
        
        /// Initialize from raw certificate data
        public init(certificateData: Data) throws {
            self.certificate = try SSHCertificate(from: certificateData, expectedKeyType: Self.publicKeyPrefix)
            
            // Extract the public key from the certificate
            guard let publicKeyData = certificate.publicKey else {
                throw SSHCertificateError.missingPublicKey
            }
            
            // ECDSA public keys in certificates are stored as EC points
            self.publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyData)
        }
        
        /// Initialize from certificate and public key
        public init(certificate: SSHCertificate, publicKey: P256.Signing.PublicKey) {
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
            certBuffer.writeSSHData(publicKey.x963Representation)
            
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
            // ECDSA certificates use the same signature validation as regular ECDSA keys
            // The signature should be an ECDSA signature
            let signatureBytes = signature.rawRepresentation
            
            // Parse the signature format (algorithm name + signature data)
            var signatureBuffer = ByteBuffer(data: signatureBytes)
            guard let algorithm = signatureBuffer.readSSHString(),
                  algorithm == "ecdsa-sha2-nistp256" else {
                return false
            }
            
            guard let signatureData = signatureBuffer.readSSHData() else {
                return false
            }
            
            // Parse ECDSA signature (r and s components)
            var sigBuffer = ByteBuffer(data: signatureData)
            guard let rData = sigBuffer.readSSHData(),
                  let sData = sigBuffer.readSSHData() else {
                return false
            }
            
            // Create signature from r and s components
            let signature = rData + sData
            guard let ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else {
                return false
            }
            
            // Verify using P256.Signing.PublicKey
            return publicKey.isValidSignature(ecdsaSignature, for: data)
        }
    }
}

// MARK: - P384 Certificate Support

extension P384.Signing {
    /// P384 certificate public key
    public final class CertificatePublicKey: NIOSSHPublicKeyProtocol, Equatable, Hashable {
        /// SSH certificate type identifier
        public static let publicKeyPrefix = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
        
        /// The underlying P384 public key
        public let publicKey: P384.Signing.PublicKey
        
        /// The certificate data
        public let certificate: SSHCertificate
        
        /// The raw representation of the public key
        public var rawRepresentation: Data {
            publicKey.x963Representation
        }
        
        /// Initialize from raw certificate data
        public init(certificateData: Data) throws {
            self.certificate = try SSHCertificate(from: certificateData, expectedKeyType: Self.publicKeyPrefix)
            
            // Extract the public key from the certificate
            guard let publicKeyData = certificate.publicKey else {
                throw SSHCertificateError.missingPublicKey
            }
            
            // ECDSA public keys in certificates are stored as EC points
            self.publicKey = try P384.Signing.PublicKey(x963Representation: publicKeyData)
        }
        
        /// Initialize from certificate and public key
        public init(certificate: SSHCertificate, publicKey: P384.Signing.PublicKey) {
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
            certBuffer.writeSSHData(publicKey.x963Representation)
            
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
            // ECDSA certificates use the same signature validation as regular ECDSA keys
            // The signature should be an ECDSA signature
            let signatureBytes = signature.rawRepresentation
            
            // Parse the signature format (algorithm name + signature data)
            var signatureBuffer = ByteBuffer(data: signatureBytes)
            guard let algorithm = signatureBuffer.readSSHString(),
                  algorithm == "ecdsa-sha2-nistp384" else {
                return false
            }
            
            guard let signatureData = signatureBuffer.readSSHData() else {
                return false
            }
            
            // Parse ECDSA signature (r and s components)
            var sigBuffer = ByteBuffer(data: signatureData)
            guard let rData = sigBuffer.readSSHData(),
                  let sData = sigBuffer.readSSHData() else {
                return false
            }
            
            // Create signature from r and s components
            let signature = rData + sData
            guard let ecdsaSignature = try? P384.Signing.ECDSASignature(rawRepresentation: signature) else {
                return false
            }
            
            // Verify using P384.Signing.PublicKey
            return publicKey.isValidSignature(ecdsaSignature, for: data)
        }
    }
}

// MARK: - P521 Certificate Support

extension P521.Signing {
    /// P521 certificate public key
    public final class CertificatePublicKey: NIOSSHPublicKeyProtocol, Equatable, Hashable {
        /// SSH certificate type identifier
        public static let publicKeyPrefix = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
        
        /// The underlying P521 public key
        public let publicKey: P521.Signing.PublicKey
        
        /// The certificate data
        public let certificate: SSHCertificate
        
        /// The raw representation of the public key
        public var rawRepresentation: Data {
            publicKey.x963Representation
        }
        
        /// Initialize from raw certificate data
        public init(certificateData: Data) throws {
            self.certificate = try SSHCertificate(from: certificateData, expectedKeyType: Self.publicKeyPrefix)
            
            // Extract the public key from the certificate
            guard let publicKeyData = certificate.publicKey else {
                throw SSHCertificateError.missingPublicKey
            }
            
            // ECDSA public keys in certificates are stored as EC points
            self.publicKey = try P521.Signing.PublicKey(x963Representation: publicKeyData)
        }
        
        /// Initialize from certificate and public key
        public init(certificate: SSHCertificate, publicKey: P521.Signing.PublicKey) {
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
            certBuffer.writeSSHData(publicKey.x963Representation)
            
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
            // ECDSA certificates use the same signature validation as regular ECDSA keys
            // The signature should be an ECDSA signature
            let signatureBytes = signature.rawRepresentation
            
            // Parse the signature format (algorithm name + signature data)
            var signatureBuffer = ByteBuffer(data: signatureBytes)
            guard let algorithm = signatureBuffer.readSSHString(),
                  algorithm == "ecdsa-sha2-nistp521" else {
                return false
            }
            
            guard let signatureData = signatureBuffer.readSSHData() else {
                return false
            }
            
            // Parse ECDSA signature (r and s components)
            var sigBuffer = ByteBuffer(data: signatureData)
            guard let rData = sigBuffer.readSSHData(),
                  let sData = sigBuffer.readSSHData() else {
                return false
            }
            
            // Create signature from r and s components
            let signature = rData + sData
            guard let ecdsaSignature = try? P521.Signing.ECDSASignature(rawRepresentation: signature) else {
                return false
            }
            
            // Verify using P521.Signing.PublicKey
            return publicKey.isValidSignature(ecdsaSignature, for: data)
        }
    }
}

