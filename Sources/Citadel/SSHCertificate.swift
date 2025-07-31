import Foundation
import NIOCore
import Crypto
import CCryptoBoringSSL

/// SSH Certificate structure
public struct SSHCertificate {
    /// Certificate types
    public enum CertificateType: UInt32 {
        case user = 1
        case host = 2
    }
    
    /// Convenience initializer for creating certificates manually (for testing)
    public init(
        nonce: Data,
        serial: UInt64,
        type: CertificateType,
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
        self.nonce = nonce
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
    
    /// Certificate nonce (32 random bytes)
    public let nonce: Data
    
    /// Certificate serial number
    public let serial: UInt64
    
    /// Certificate type (1 = user, 2 = host)
    public let type: CertificateType
    
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
        
        // Store the original buffer for signature verification
        var originalBuffer = buffer
        
        // Read the key type
        guard let keyType = buffer.readSSHString(),
              keyType == expectedKeyType else {
            throw SSHCertificateError.invalidCertificateType
        }
        
        // Skip nonce for now - it's parsed after the public key, per OpenSSH
        guard let _ = buffer.readSSHData() else {
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
        
        // Now read the nonce (after public key, matching OpenSSH order)
        // Reset to original buffer and skip past key type
        var nonceBuffer = originalBuffer
        _ = nonceBuffer.readSSHString() // skip key type
        guard let nonce = nonceBuffer.readSSHData() else {
            throw SSHCertificateError.missingNonce
        }
        self.nonce = nonce
        
        // Read serial
        guard let serial = buffer.readInteger(as: UInt64.self) else {
            throw SSHCertificateError.missingSerial
        }
        self.serial = serial
        
        // Read type
        guard let typeValue = buffer.readInteger(as: UInt32.self),
              let type = CertificateType(rawValue: typeValue) else {
            throw SSHCertificateError.invalidCertificateType
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
        
        // Verify CA signature
        let signedLength = originalBuffer.readableBytes - buffer.readableBytes - signature.count - 4
        let signedData = Data(originalBuffer.readBytes(length: signedLength)!)
        
        // Parse CA key from signatureKey blob
        guard let caKey = try? Self.parseCAKey(from: signatureKey) else {
            throw SSHCertificateError.invalidSignatureKey
        }
        
        // Verify signature
        guard try Self.verifySignature(signature, for: signedData, with: caKey) else {
            throw SSHCertificateError.invalidSignature
        }
    }
    
    /// Parse CA key from blob
    private static func parseCAKey(from data: Data) throws -> Any {
        var buffer = ByteBuffer(data: data)
        guard let keyType = buffer.readSSHString() else {
            throw SSHCertificateError.invalidSignatureKey
        }
        
        if keyType == "ssh-ed25519" {
            guard let publicKeyData = buffer.readSSHData(),
                  publicKeyData.count == 32 else {
                throw SSHCertificateError.invalidSignatureKey
            }
            return try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        } else if keyType.hasPrefix("ecdsa-sha2-") {
            guard let curveIdentifier = buffer.readSSHString(),
                  let pointData = buffer.readSSHData() else {
                throw SSHCertificateError.invalidSignatureKey
            }
            
            switch curveIdentifier {
            case "nistp256":
                return try P256.Signing.PublicKey(x963Representation: pointData)
            case "nistp384":
                return try P384.Signing.PublicKey(x963Representation: pointData)
            case "nistp521":
                return try P521.Signing.PublicKey(x963Representation: pointData)
            default:
                throw SSHCertificateError.invalidSignatureKey
            }
        } else if keyType == "ssh-rsa" || keyType.hasPrefix("rsa-sha2-") {
            guard let eData = buffer.readSSHData(),
                  let nData = buffer.readSSHData() else {
                throw SSHCertificateError.invalidSignatureKey
            }
            
            // Create RSA public key from e and n using the same method as RSA.PublicKey.read
            let publicExponent = CCryptoBoringSSL_BN_bin2bn(Array(eData), eData.count, nil)!
            let modulus = CCryptoBoringSSL_BN_bin2bn(Array(nData), nData.count, nil)!
            
            return Insecure.RSA.PublicKey(publicExponent: publicExponent, modulus: modulus)
        }
        
        throw SSHCertificateError.invalidSignatureKey
    }
    
    /// Normalize ECDSA signature component to expected size
    /// SSH uses bignum format which may have leading zeros that need to be stripped
    /// or may need padding if the value is smaller than expected
    private static func normalizeECDSAComponent(_ data: Data, expectedSize: Int) -> Data {
        if data.count == expectedSize {
            return data
        } else if data.count > expectedSize {
            // Remove leading zeros
            let leadingZeros = data.prefix(while: { $0 == 0 })
            let trimmed = data.dropFirst(leadingZeros.count)
            if trimmed.count == expectedSize {
                return trimmed
            } else if trimmed.count < expectedSize {
                // Pad with zeros after removing too many
                let padding = Data(repeating: 0, count: expectedSize - trimmed.count)
                return padding + trimmed
            } else {
                // Still too big, take the last expectedSize bytes
                return trimmed.suffix(expectedSize)
            }
        } else {
            // Pad with leading zeros
            let padding = Data(repeating: 0, count: expectedSize - data.count)
            return padding + data
        }
    }
    
    /// Verify signature
    private static func verifySignature(_ signature: Data, for data: Data, with key: Any) throws -> Bool {
        var sigBuffer = ByteBuffer(data: signature)
        guard let sigType = sigBuffer.readSSHString(),
              let sigBlob = sigBuffer.readSSHData() else {
            return false
        }
        
        if let ed25519Key = key as? Curve25519.Signing.PublicKey {
            guard sigType == "ssh-ed25519" else { return false }
            return ed25519Key.isValidSignature(sigBlob, for: data)
        } else if let p256Key = key as? P256.Signing.PublicKey {
            guard sigType == "ecdsa-sha2-nistp256" else { return false }
            // SSH ECDSA signatures store r and s as separate SSH strings with potential leading zeros
            var sigBlobBuffer = ByteBuffer(data: sigBlob)
            guard let rData = sigBlobBuffer.readSSHData(),
                  let sData = sigBlobBuffer.readSSHData() else {
                return false
            }
            
            // SSH uses bignum format which may include leading zeros
            // P256 expects exactly 32 bytes for each component
            let r = normalizeECDSAComponent(rData, expectedSize: 32)
            let s = normalizeECDSAComponent(sData, expectedSize: 32)
            let rawSig = r + s
            
            guard let ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: rawSig) else {
                return false
            }
            return p256Key.isValidSignature(ecdsaSignature, for: SHA256.hash(data: data))
        } else if let p384Key = key as? P384.Signing.PublicKey {
            guard sigType == "ecdsa-sha2-nistp384" else { return false }
            // SSH ECDSA signatures store r and s as separate SSH strings with potential leading zeros
            var sigBlobBuffer = ByteBuffer(data: sigBlob)
            guard let rData = sigBlobBuffer.readSSHData(),
                  let sData = sigBlobBuffer.readSSHData() else {
                return false
            }
            
            // SSH uses bignum format which may include leading zeros
            // P384 expects exactly 48 bytes for each component
            let r = normalizeECDSAComponent(rData, expectedSize: 48)
            let s = normalizeECDSAComponent(sData, expectedSize: 48)
            let rawSig = r + s
            
            guard let ecdsaSignature = try? P384.Signing.ECDSASignature(rawRepresentation: rawSig) else {
                return false
            }
            return p384Key.isValidSignature(ecdsaSignature, for: SHA384.hash(data: data))
        } else if let p521Key = key as? P521.Signing.PublicKey {
            guard sigType == "ecdsa-sha2-nistp521" else { return false }
            // SSH ECDSA signatures store r and s as separate SSH strings with potential leading zeros
            var sigBlobBuffer = ByteBuffer(data: sigBlob)
            guard let rData = sigBlobBuffer.readSSHData(),
                  let sData = sigBlobBuffer.readSSHData() else {
                return false
            }
            
            // SSH uses bignum format which may include leading zeros
            // P521 expects exactly 66 bytes for each component
            let r = normalizeECDSAComponent(rData, expectedSize: 66)
            let s = normalizeECDSAComponent(sData, expectedSize: 66)
            let rawSig = r + s
            
            guard let ecdsaSignature = try? P521.Signing.ECDSASignature(rawRepresentation: rawSig) else {
                return false
            }
            return p521Key.isValidSignature(ecdsaSignature, for: SHA512.hash(data: data))
        } else if let rsaKey = key as? Insecure.RSA.PublicKey {
            // RSA signatures can use different hash algorithms
            let hashAlgorithm: Insecure.RSA.SignatureHashAlgorithm
            switch sigType {
            case "ssh-rsa":
                hashAlgorithm = .sha1
            case "rsa-sha2-256":
                hashAlgorithm = .sha256
            case "rsa-sha2-512":
                hashAlgorithm = .sha512
            default:
                return false
            }
            
            guard let signature = try? Insecure.RSA.Signature(rawRepresentation: sigBlob, algorithm: hashAlgorithm) else {
                return false
            }
            
            return rsaKey.isValidSignature(signature, for: data)
        }
        
        return false
    }
}

/// SSH Certificate errors
public enum SSHCertificateError: Error {
    case invalidCertificateType
    case missingNonce
    case missingPublicKey
    case invalidPublicKey
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
    case invalidSignatureKey
    case invalidSignature
    case unsupportedKeyType
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