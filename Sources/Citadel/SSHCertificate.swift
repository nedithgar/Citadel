import Foundation
import NIOCore

/// SSH Certificate structure
public struct SSHCertificate {
    
    /// Convenience initializer for creating certificates manually (for testing)
    public init(
        serial: UInt64,
        type: UInt32,
        keyId: String,
        validPrincipals: [String],
        validAfter: UInt64,
        validBefore: UInt64,
        criticalOptions: [(String, Data)],
        extensions: [(String, Data)],
        reserved: Data,
        signatureKey: Data,
        signature: Data,
        publicKey: Data?
    ) {
        self.serial = serial
        self.type = type
        self.keyId = keyId
        self.validPrincipals = validPrincipals
        self.validAfter = validAfter
        self.validBefore = validBefore
        self.criticalOptions = criticalOptions
        self.extensions = extensions
        self.reserved = reserved
        self.signatureKey = signatureKey
        self.signature = signature
        self.publicKey = publicKey
    }
    
    /// Certificate serial number
    public let serial: UInt64
    
    /// Certificate type (1 = user, 2 = host)
    public let type: UInt32
    
    /// Key ID (free-form text)
    public let keyId: String
    
    /// Valid principals (usernames/hostnames)
    public let validPrincipals: [String]
    
    /// Valid after timestamp (seconds since epoch)
    public let validAfter: UInt64
    
    /// Valid before timestamp (seconds since epoch)
    public let validBefore: UInt64
    
    /// Critical options
    public let criticalOptions: [(String, Data)]
    
    /// Extensions
    public let extensions: [(String, Data)]
    
    /// Reserved field
    public let reserved: Data
    
    /// CA public key
    public let signatureKey: Data
    
    /// CA signature
    public let signature: Data
    
    /// The embedded public key data
    public let publicKey: Data?
    
    /// Initialize from raw certificate data with expected key type
    public init(from data: Data, expectedKeyType: String) throws {
        var buffer = ByteBuffer(data: data)
        
        // Read the key type
        guard let keyType = buffer.readSSHString(),
              keyType == expectedKeyType else {
            throw SSHCertificateError.invalidCertificateType
        }
        
        // Read nonce
        guard buffer.readSSHData() != nil else {
            throw SSHCertificateError.missingNonce
        }
        
        // Read public key
        // Different key types store public keys differently in certificates
        if keyType.contains("ssh-rsa-cert") || keyType.contains("rsa-sha2") {
            // RSA: Read e and n components and reconstruct the public key data
            guard let e = buffer.readSSHData(),
                  let n = buffer.readSSHData() else {
                throw SSHCertificateError.missingPublicKey
            }
            
            // Reconstruct the public key data in the format expected by RSA.PublicKey
            var publicKeyBuffer = ByteBufferAllocator().buffer(capacity: e.count + n.count + 8)
            publicKeyBuffer.writeSSHData(e)
            publicKeyBuffer.writeSSHData(n)
            self.publicKey = Data(publicKeyBuffer.readableBytesView)
        } else if keyType.contains("ecdsa-sha2") {
            // ECDSA: Read curve identifier and point data
            guard let _ = buffer.readSSHString(), // curve identifier
                  let pointData = buffer.readSSHData() else {
                throw SSHCertificateError.missingPublicKey
            }
            
            // ECDSA certificates store the point data in x963 format (04 || x || y)
            // which is what P256/P384/P521.Signing.PublicKey expects
            self.publicKey = pointData
        } else {
            // Ed25519: Read as a single blob
            guard let publicKeyData = buffer.readSSHData() else {
                throw SSHCertificateError.missingPublicKey
            }
            self.publicKey = publicKeyData
        }
        
        // Read serial
        guard let serial = buffer.readInteger(as: UInt64.self) else {
            throw SSHCertificateError.missingSerial
        }
        self.serial = serial
        
        // Read type
        guard let type = buffer.readInteger(as: UInt32.self) else {
            throw SSHCertificateError.missingType
        }
        self.type = type
        
        // Read key ID
        guard let keyId = buffer.readSSHString() else {
            throw SSHCertificateError.missingKeyId
        }
        self.keyId = keyId
        
        // Read valid principals
        guard var principalsBuffer = buffer.readSSHBuffer() else {
            throw SSHCertificateError.missingPrincipals
        }
        var principals: [String] = []
        while principalsBuffer.readableBytes > 0 {
            guard let principal = principalsBuffer.readSSHString() else {
                throw SSHCertificateError.invalidPrincipal
            }
            principals.append(principal)
        }
        self.validPrincipals = principals
        
        // Read validity period
        guard let validAfter = buffer.readInteger(as: UInt64.self) else {
            throw SSHCertificateError.missingValidAfter
        }
        self.validAfter = validAfter
        
        guard let validBefore = buffer.readInteger(as: UInt64.self) else {
            throw SSHCertificateError.missingValidBefore
        }
        self.validBefore = validBefore
        
        // Read critical options
        guard var criticalOptionsBuffer = buffer.readSSHBuffer() else {
            throw SSHCertificateError.missingCriticalOptions
        }
        var criticalOptions: [(String, Data)] = []
        while criticalOptionsBuffer.readableBytes > 0 {
            guard let name = criticalOptionsBuffer.readSSHString(),
                  let value = criticalOptionsBuffer.readSSHData() else {
                throw SSHCertificateError.invalidCriticalOption
            }
            criticalOptions.append((name, value))
        }
        self.criticalOptions = criticalOptions
        
        // Read extensions
        guard var extensionsBuffer = buffer.readSSHBuffer() else {
            throw SSHCertificateError.missingExtensions
        }
        var extensions: [(String, Data)] = []
        while extensionsBuffer.readableBytes > 0 {
            guard let name = extensionsBuffer.readSSHString(),
                  let value = extensionsBuffer.readSSHData() else {
                throw SSHCertificateError.invalidExtension
            }
            extensions.append((name, value))
        }
        self.extensions = extensions
        
        // Read reserved
        guard let reserved = buffer.readSSHData() else {
            throw SSHCertificateError.missingReserved
        }
        self.reserved = reserved
        
        // Read signature key
        guard let signatureKey = buffer.readSSHData() else {
            throw SSHCertificateError.missingSignatureKey
        }
        self.signatureKey = signatureKey
        
        // Read signature
        guard let signature = buffer.readSSHData() else {
            throw SSHCertificateError.missingSignature
        }
        self.signature = signature
    }
}

/// SSH Certificate errors
public enum SSHCertificateError: Error {
    case invalidCertificateType
    case missingNonce
    case missingPublicKey
    case missingSerial
    case missingType
    case missingKeyId
    case invalidKeyId
    case missingPrincipals
    case invalidPrincipal
    case missingValidAfter
    case missingValidBefore
    case missingCriticalOptions
    case invalidCriticalOption
    case missingExtensions
    case invalidExtension
    case missingReserved
    case missingSignatureKey
    case missingSignature
}

// MARK: - Private extensions for certificate parsing

extension ByteBuffer {
    /// Write SSH data (length-prefixed bytes)
    @discardableResult
    mutating func writeSSHData(_ data: Data) -> Int {
        let written = writeInteger(UInt32(data.count))
        return written + writeBytes(data)
    }
}