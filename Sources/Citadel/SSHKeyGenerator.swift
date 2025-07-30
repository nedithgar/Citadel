import Foundation
import Crypto
import _CryptoExtras
import NIOSSH
import NIOCore

/// Represents a generated SSH key pair with both private and public keys
public struct SSHKeyPair: Sendable {
    /// The wrapped NIOSSH private key
    public let nioSSHPrivateKey: NIOSSHPrivateKey
    
    /// The underlying private key (for direct access when needed)
    private let underlyingPrivateKey: Any
    
    /// The type of the key
    public let keyType: SSHKeyGenerationType
    
    /// Initialize with various key types
    internal init(rsaKey: Insecure.RSA.PrivateKey, keyType: SSHKeyGenerationType) {
        self.nioSSHPrivateKey = NIOSSHPrivateKey(custom: rsaKey)
        self.underlyingPrivateKey = rsaKey
        self.keyType = keyType
    }
    
    internal init(ed25519Key: Curve25519.Signing.PrivateKey, keyType: SSHKeyGenerationType) {
        self.nioSSHPrivateKey = NIOSSHPrivateKey(ed25519Key: ed25519Key)
        self.underlyingPrivateKey = ed25519Key
        self.keyType = keyType
    }
    
    internal init(p256Key: P256.Signing.PrivateKey, keyType: SSHKeyGenerationType) {
        self.nioSSHPrivateKey = NIOSSHPrivateKey(p256Key: p256Key)
        self.underlyingPrivateKey = p256Key
        self.keyType = keyType
    }
    
    internal init(p384Key: P384.Signing.PrivateKey, keyType: SSHKeyGenerationType) {
        self.nioSSHPrivateKey = NIOSSHPrivateKey(p384Key: p384Key)
        self.underlyingPrivateKey = p384Key
        self.keyType = keyType
    }
    
    internal init(p521Key: P521.Signing.PrivateKey, keyType: SSHKeyGenerationType) {
        self.nioSSHPrivateKey = NIOSSHPrivateKey(p521Key: p521Key)
        self.underlyingPrivateKey = p521Key
        self.keyType = keyType
    }
    
    /// Exports the private key in OpenSSH format
    /// - Parameters:
    ///   - comment: Optional comment to include in the key (default: empty)
    ///   - passphrase: Optional passphrase to encrypt the key (default: nil for unencrypted)
    ///   - cipher: The cipher to use for encryption when passphrase is provided (default: "aes256-ctr" when passphrase is set, "none" otherwise)
    ///             Supported values: "none", "aes128-ctr", "aes256-ctr"
    /// - Returns: The private key in OpenSSH format
    /// - Throws: An error if the key type doesn't support OpenSSH format
    public func privateKeyOpenSSHString(comment: String = "", passphrase: String? = nil, cipher: String? = nil) throws -> String {
        // Determine the actual cipher to use
        let actualCipher: String
        if let cipher = cipher {
            actualCipher = cipher
        } else if passphrase != nil {
            actualCipher = "aes256-ctr"  // Default to aes256-ctr when passphrase is provided
        } else {
            actualCipher = "none"
        }
        
        switch keyType {
        case .rsa:
            // RSA keys need to be wrapped in OpenSSH format
            // This would require implementing OpenSSH key serialization for RSA
            throw SSHKeyGeneratorError.unsupportedExportFormat("OpenSSH format for RSA keys not yet implemented")
            
        case .ed25519:
            let ed25519Key = underlyingPrivateKey as! Curve25519.Signing.PrivateKey
            return try ed25519Key.makeSSHRepresentation(comment: comment, passphrase: passphrase, cipher: actualCipher)
            
        case .ecdsaP256:
            let p256Key = underlyingPrivateKey as! P256.Signing.PrivateKey
            return try p256Key.makeSSHRepresentation(comment: comment, passphrase: passphrase, cipher: actualCipher)
            
        case .ecdsaP384:
            let p384Key = underlyingPrivateKey as! P384.Signing.PrivateKey
            return try p384Key.makeSSHRepresentation(comment: comment, passphrase: passphrase, cipher: actualCipher)
            
        case .ecdsaP521:
            let p521Key = underlyingPrivateKey as! P521.Signing.PrivateKey
            return try p521Key.makeSSHRepresentation(comment: comment, passphrase: passphrase, cipher: actualCipher)
        }
    }
    
    /// Exports the public key in OpenSSH format
    /// - Returns: The public key in OpenSSH format (e.g., "ssh-ed25519 AAAA...")
    /// - Throws: An error if the export fails
    public func publicKeyOpenSSHString() throws -> String {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        
        // Write the key type prefix
        let keyTypeString: String
        switch keyType {
        case .rsa:
            keyTypeString = "ssh-rsa"
        case .ed25519:
            keyTypeString = "ssh-ed25519"
        case .ecdsaP256:
            keyTypeString = "ecdsa-sha2-nistp256"
        case .ecdsaP384:
            keyTypeString = "ecdsa-sha2-nistp384"
        case .ecdsaP521:
            keyTypeString = "ecdsa-sha2-nistp521"
        }
        
        buffer.writeSSHString(keyTypeString)
        
        // Write the public key data
        _ = nioSSHPrivateKey.publicKey.write(to: &buffer)
        
        // Encode to base64
        let keyData = buffer.readData(length: buffer.readableBytes)!
        let base64Key = keyData.base64EncodedString()
        
        return "\(keyTypeString) \(base64Key)"
    }
    
    /// Exports the private key in PEM format (where supported)
    /// - Returns: The private key in PEM format, or nil if not supported
    public func privateKeyPEMString() throws -> String? {
        switch keyType {
        case .rsa:
            // RSA PEM export would require additional implementation
            return nil
            
        case .ed25519:
            // Ed25519 doesn't have standard PEM format in Swift Crypto
            return nil
            
        case .ecdsaP256:
            let p256Key = underlyingPrivateKey as! P256.Signing.PrivateKey
            return p256Key.pemRepresentation
            
        case .ecdsaP384:
            let p384Key = underlyingPrivateKey as! P384.Signing.PrivateKey
            return p384Key.pemRepresentation
            
        case .ecdsaP521:
            let p521Key = underlyingPrivateKey as! P521.Signing.PrivateKey
            return p521Key.pemRepresentation
        }
    }
}

/// Supported SSH key types for generation
public enum SSHKeyGenerationType: Sendable {
    /// RSA key with specified bit size
    case rsa(bits: Int)
    /// Ed25519 key (recommended)
    case ed25519
    /// ECDSA with NIST P-256 curve
    case ecdsaP256
    /// ECDSA with NIST P-384 curve
    case ecdsaP384
    /// ECDSA with NIST P-521 curve
    case ecdsaP521
}

/// Supported ECDSA curves
public enum ECDSACurve: Sendable {
    /// NIST P-256 curve
    case p256
    /// NIST P-384 curve
    case p384
    /// NIST P-521 curve
    case p521
}

/// High-level SSH key generator
public struct SSHKeyGenerator {
    /// Generate an RSA key pair
    /// - Parameter bits: The key size in bits (2048, 3072, or 4096 recommended)
    /// - Returns: A new RSA key pair
    public static func generateRSA(bits: Int = 2048) -> SSHKeyPair {
        let privateKey = Insecure.RSA.PrivateKey(bits: bits)
        return SSHKeyPair(rsaKey: privateKey, keyType: .rsa(bits: bits))
    }
    
    /// Generate an Ed25519 key pair (recommended for most use cases)
    /// - Returns: A new Ed25519 key pair
    public static func generateEd25519() -> SSHKeyPair {
        let privateKey = Curve25519.Signing.PrivateKey()
        return SSHKeyPair(ed25519Key: privateKey, keyType: .ed25519)
    }
    
    /// Generate an ECDSA key pair
    /// - Parameter curve: The elliptic curve to use
    /// - Returns: A new ECDSA key pair
    public static func generateECDSA(curve: ECDSACurve) -> SSHKeyPair {
        switch curve {
        case .p256:
            let privateKey = P256.Signing.PrivateKey()
            return SSHKeyPair(p256Key: privateKey, keyType: .ecdsaP256)
        case .p384:
            let privateKey = P384.Signing.PrivateKey()
            return SSHKeyPair(p384Key: privateKey, keyType: .ecdsaP384)
        case .p521:
            let privateKey = P521.Signing.PrivateKey()
            return SSHKeyPair(p521Key: privateKey, keyType: .ecdsaP521)
        }
    }
    
    /// Generate a key pair with the specified type
    /// - Parameter type: The type of key to generate (default: Ed25519)
    /// - Returns: A new key pair of the specified type
    public static func generate(type: SSHKeyGenerationType = .ed25519) -> SSHKeyPair {
        switch type {
        case .rsa(let bits):
            return generateRSA(bits: bits)
        case .ed25519:
            return generateEd25519()
        case .ecdsaP256:
            return generateECDSA(curve: .p256)
        case .ecdsaP384:
            return generateECDSA(curve: .p384)
        case .ecdsaP521:
            return generateECDSA(curve: .p521)
        }
    }
}

/// Errors that can occur during key generation or export
public enum SSHKeyGeneratorError: Error {
    /// The key type is not supported for the requested operation
    case unsupportedKeyType
    /// The export format is not supported for this key type
    case unsupportedExportFormat(String)
}

// MARK: - Convenience Extensions

extension SSHKeyPair {
    /// Create an authentication method for use with SSHClient
    /// - Parameter username: The username to authenticate with
    /// - Returns: An SSH authentication method
    public func authenticationMethod(username: String) -> SSHAuthenticationMethod {
        // We need to properly identify and cast the key types
        // Since we control the creation, we can safely force cast based on keyType
        switch keyType {
        case .rsa:
            let rsaKey = underlyingPrivateKey as! Insecure.RSA.PrivateKey
            return .rsa(username: username, privateKey: rsaKey)
            
        case .ed25519:
            let ed25519Key = underlyingPrivateKey as! Curve25519.Signing.PrivateKey
            return .ed25519(username: username, privateKey: ed25519Key)
            
        case .ecdsaP256:
            let p256Key = underlyingPrivateKey as! P256.Signing.PrivateKey
            return .p256(username: username, privateKey: p256Key)
            
        case .ecdsaP384:
            let p384Key = underlyingPrivateKey as! P384.Signing.PrivateKey
            return .p384(username: username, privateKey: p384Key)
            
        case .ecdsaP521:
            let p521Key = underlyingPrivateKey as! P521.Signing.PrivateKey
            return .p521(username: username, privateKey: p521Key)
        }
    }
}