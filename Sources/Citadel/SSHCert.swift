import CCryptoBoringSSL
import BigInt
import Foundation
import Crypto
import NIO
import NIOSSH

public struct InvalidOpenSSHKey: Error {
    public enum UnsupportedFeature: String {
        case multipleKeys, unsupportedPublicKeyType, unsupportedKDF, unsupportedCipher
    }

    let reason: String

    static let invalidUTF8String = InvalidOpenSSHKey(reason: "invalidUTF8String")
    static let missingPublicKeyBuffer = InvalidOpenSSHKey(reason: "missingPublicKeyBuffer")
    static let missingPrivateKeyBuffer = InvalidOpenSSHKey(reason: "missingPrivateKeyBuffer")
    static let missingPublicKeyInPrivateKey = InvalidOpenSSHKey(reason: "missingPublicKeyInPrivateKey")
    static let missingComment = InvalidOpenSSHKey(reason: "missingComment")
    static let invalidCheck = InvalidOpenSSHKey(reason: "invalidCheck")
    static let invalidPublicKeyInPrivateKey = InvalidOpenSSHKey(reason: "invalidPublicKeyInPrivateKey")
    static let invalidLayout = InvalidOpenSSHKey(reason: "invalidLayout")
    static let invalidPadding = InvalidOpenSSHKey(reason: "invalidPadding")
    static let invalidOpenSSHBoundary = InvalidOpenSSHKey(reason: "invalidOpenSSHBoundary")
    static let invalidBase64Payload = InvalidOpenSSHKey(reason: "invalidBase64Payload")
    static let invalidOpenSSHPrefix = InvalidOpenSSHKey(reason: "invalidOpenSSHPrefix")
    static func unsupportedFeature(_ feature: UnsupportedFeature) -> InvalidOpenSSHKey {
        InvalidOpenSSHKey(reason: "UnsupportedFeature: \(feature.rawValue)")
    }
    static let invalidPublicKeyPrefix = InvalidOpenSSHKey(reason: "invalidPublicKeyPrefix")
    static let invalidOrUnsupportedBCryptConfig = InvalidOpenSSHKey(reason: "invalidOrUnsupportedBCryptConfig")
    static let unexpectedKDFNoneOptions = InvalidOpenSSHKey(reason: "unexpectedKDFNoneOptions")
}

public typealias InvalidKey = InvalidOpenSSHKey

extension Curve25519.Signing.PublicKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> Curve25519.Signing.PublicKey {
        guard var publicKeyBuffer = buffer.readSSHBuffer() else {
            throw InvalidOpenSSHKey.missingPublicKeyBuffer
        }
        
        return try self.init(rawRepresentation: publicKeyBuffer.readBytes(length: publicKeyBuffer.readableBytes)!)
    }
    
    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeData(self.rawRepresentation)
    }
}

extension Curve25519.Signing.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = Curve25519.Signing.PublicKey
    static var publicKeyPrefix: String { "ssh-ed25519" }
    static var privateKeyPrefix: String { "ssh-ed25519" }
    static var keyType: OpenSSH.KeyType { .sshED25519 }
    
    func getPublicKey() -> Curve25519.Signing.PublicKey {
        self.publicKey
    }
    
    /// Creates a new OpenSSH formatted private key
    /// - Parameters:
    ///   - comment: Optional comment to include in the key
    ///   - passphrase: Optional passphrase to encrypt the key
    ///   - cipher: Cipher to use for encryption (default: "none")
    ///   - rounds: Number of BCrypt rounds for key derivation (default: 16)
    /// - Returns: OpenSSH formatted private key string
    public func makeSSHRepresentation(
        comment: String = "",
        passphrase: String? = nil,
        cipher: String = "none",
        rounds: Int = 16
    ) throws -> String {
        try (self as any OpenSSHPrivateKey).makeSSHRepresentation(
            comment: comment,
            passphrase: passphrase,
            cipher: cipher,
            rounds: rounds
        )
    }
    
    /// Creates a new Curve25519 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public init(sshEd25519 data: Data, decryptionKey: Data? = nil) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(sshEd25519: string, decryptionKey: decryptionKey)
        } else {
            throw InvalidOpenSSHKey.invalidUTF8String
        }
    }
    
    /// Creates a new Curve25519 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public init(sshEd25519 key: String, decryptionKey: Data? = nil) throws {
        self = try OpenSSH.PrivateKey<Curve25519.Signing.PrivateKey>.init(string: key, decryptionKey: decryptionKey).privateKey
    }
}

extension Insecure.RSA.PublicKey: ByteBufferConvertible {
    func write(to buffer: inout ByteBuffer) {
        let _: Int = self.write(to: &buffer)
    }
}

extension Insecure.RSA.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = Insecure.RSA.PublicKey
    
    static var publicKeyPrefix: String { "ssh-rsa" }
    static var privateKeyPrefix: String { "ssh-rsa" }
    static var keyType: OpenSSH.KeyType { .sshRSA }
    static var wrapPublicKeyInCompositeString: Bool { false }
    
    func getPublicKey() -> Insecure.RSA.PublicKey {
        _publicKey
    }
    
    /// Creates a new OpenSSH formatted private key
    /// - Parameters:
    ///   - comment: Optional comment to include in the key
    ///   - passphrase: Optional passphrase to encrypt the key
    ///   - cipher: Cipher to use for encryption (default: "none")
    ///   - rounds: Number of BCrypt rounds for key derivation (default: 16)
    /// - Returns: OpenSSH formatted private key string
    /// - Note: RSA keys generated by Citadel now include all CRT parameters (p, q, iqmp).
    ///         Keys imported from other sources may not have these parameters, in which case
    ///         they will be exported with placeholder values.
    ///         RSA signatures support modern hash algorithms: SHA-1 (legacy), SHA-256, and SHA-512.
    public func makeSSHRepresentation(
        comment: String = "",
        passphrase: String? = nil,
        cipher: String = "none",
        rounds: Int = 16
    ) throws -> String {
        try (self as any OpenSSHPrivateKey).makeSSHRepresentation(
            comment: comment,
            passphrase: passphrase,
            cipher: cipher,
            rounds: rounds
        )
    }
    
    /// Creates a new RSA private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public convenience init(sshRsa data: Data, decryptionKey: Data? = nil) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(sshRsa: string, decryptionKey: decryptionKey)
        } else {
            throw InvalidOpenSSHKey.invalidUTF8String
        }
    }
    
    /// Creates a new RSA private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public convenience init(sshRsa key: String, decryptionKey: Data? = nil) throws {
        let privateKey = try OpenSSH.PrivateKey<Insecure.RSA.PrivateKey>.init(string: key, decryptionKey: decryptionKey).privateKey
        let publicKey = privateKey.getPublicKey()
        
        // Copy, so that our values stored in `privateKey` aren't freed when exciting the initializers scope
        let modulus = CCryptoBoringSSL_BN_new()!
        let publicExponent = CCryptoBoringSSL_BN_new()!
        let privateExponent = CCryptoBoringSSL_BN_new()!
        
        CCryptoBoringSSL_BN_copy(modulus, publicKey.modulus)
        CCryptoBoringSSL_BN_copy(publicExponent, publicKey.publicExponent)
        CCryptoBoringSSL_BN_copy(privateExponent, privateKey.privateExponent)
        
        self.init(privateExponent: privateExponent, publicExponent: publicExponent, modulus: modulus)
    }
}

extension P256.Signing.PrivateKey {
    /// Creates a new P256 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public init(sshECDSA data: Data, decryptionKey: Data? = nil) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(sshECDSA: string, decryptionKey: decryptionKey)
        } else {
            throw InvalidOpenSSHKey.invalidUTF8String
        }
    }
    
    /// Creates a new P256 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public init(sshECDSA key: String, decryptionKey: Data? = nil) throws {
        let privateKey = try OpenSSH.PrivateKey<P256.Signing.PrivateKey>(string: key, decryptionKey: decryptionKey).privateKey
        try self.init(rawRepresentation: privateKey.rawRepresentation)
    }
}

extension P384.Signing.PrivateKey {
    /// Creates a new P384 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public init(sshECDSA data: Data, decryptionKey: Data? = nil) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(sshECDSA: string, decryptionKey: decryptionKey)
        } else {
            throw InvalidOpenSSHKey.invalidUTF8String
        }
    }
    
    /// Creates a new P384 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public init(sshECDSA key: String, decryptionKey: Data? = nil) throws {
        let privateKey = try OpenSSH.PrivateKey<P384.Signing.PrivateKey>(string: key, decryptionKey: decryptionKey).privateKey
        try self.init(rawRepresentation: privateKey.rawRepresentation)
    }
}

extension P521.Signing.PrivateKey {
    /// Creates a new P521 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public init(sshECDSA data: Data, decryptionKey: Data? = nil) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(sshECDSA: string, decryptionKey: decryptionKey)
        } else {
            throw InvalidOpenSSHKey.invalidUTF8String
        }
    }
    
    /// Creates a new P521 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public init(sshECDSA key: String, decryptionKey: Data? = nil) throws {
        let privateKey = try OpenSSH.PrivateKey<P521.Signing.PrivateKey>(string: key, decryptionKey: decryptionKey).privateKey
        try self.init(rawRepresentation: privateKey.rawRepresentation)
    }
}
