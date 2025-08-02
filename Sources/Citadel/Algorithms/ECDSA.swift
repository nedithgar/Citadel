import Foundation
import Crypto
import _CryptoExtras
import NIOCore
import BigInt

// MARK: - Constants

/// ECDSA point format identifier for uncompressed points
/// In the x963 representation, uncompressed points start with 0x04
private let uncompressedPointPrefix: UInt8 = 0x04

// MARK: - Helper Functions

/// Writes ECDSA public key data to a buffer in SSH format
/// - Parameters:
///   - buffer: The buffer to write to
///   - curveName: The curve name (e.g., "nistp256", "nistp384", "nistp521"), if provided
///   - publicKeyData: The public key data in x963 representation
/// - Returns: The number of bytes written
@discardableResult
private func writeECDSAPublicKey(to buffer: inout ByteBuffer, curveName: String? = nil, publicKeyData: Data) -> Int {
    let start = buffer.writerIndex
    if let curveName = curveName {
        buffer.writeSSHString(curveName)
    }
    buffer.writeSSHString(publicKeyData)
    return buffer.writerIndex - start
}

/// Processes ECDSA private key data by validating its size and removing the leading zero byte if present.
/// 
/// SSH bignum format may include a leading zero byte to ensure the number is interpreted as unsigned.
/// This function removes that zero byte if present and validates that the resulting data matches
/// the expected key size for the curve.
///
/// - Parameters:
///   - privateKeyData: The raw private key data from SSH format
///   - expectedKeySize: The expected size in bytes for the specific curve (32 for P-256, 48 for P-384, 66 for P-521)
/// - Returns: The processed private key data with the correct size
/// - Throws: `InvalidOpenSSHKey.invalidLayout` if the data size is invalid
private func processECDSAPrivateKeyData(_ privateKeyData: Data, expectedKeySize: Int) throws -> Data {
    // SSH bignums may have a leading zero byte to ensure they're treated as positive
    if privateKeyData.count == expectedKeySize + 1 && privateKeyData[0] == 0 {
        // Remove the leading zero byte
        return privateKeyData.dropFirst()
    } else if privateKeyData.count == expectedKeySize {
        // Already the correct size
        return privateKeyData
    } else if privateKeyData.count < expectedKeySize {
        // Pad with leading zeros if too short
        let padding = Data(repeating: 0, count: expectedKeySize - privateKeyData.count)
        return padding + privateKeyData
    } else {
        // Invalid size - too large
        throw InvalidOpenSSHKey.invalidLayout
    }
}

extension P256.Signing.PrivateKey: ByteBufferConvertible {
    public static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        // For ECDSA, the private key section contains:
        // 1. Curve name and public key (for non-cert keys)
        // 2. Private key exponent as a bignum
        guard
            let curveName = buffer.readSSHString(),
            let _ = buffer.readSSHString(), // public key - we don't need it for reconstruction
            let privateKeyData = buffer.readSSHBignum()
        else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        guard curveName == "nistp256" else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        // Process the private key data to validate size and remove leading zero if present
        let keyData = try processECDSAPrivateKeyData(privateKeyData, expectedKeySize: 32)
        
        return try P256.Signing.PrivateKey(rawRepresentation: keyData)
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        let start = buffer.writerIndex
        
        // For ECDSA, the private key section contains:
        // 1. Curve name and public key (for non-cert keys)
        // 2. Private key exponent as a bignum
        writeECDSAPublicKey(to: &buffer, curveName: "nistp256", publicKeyData: publicKey.x963Representation)
        
        // Write private key as bignum - SSH bignum format preserves all bytes
        let privateKeyData = self.rawRepresentation
        buffer.writeInteger(UInt32(privateKeyData.count))
        buffer.writeBytes(privateKeyData)
        
        return buffer.writerIndex - start
    }
}

extension P384.Signing.PrivateKey: ByteBufferConvertible {
    public static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        // For ECDSA, the private key section contains:
        // 1. Curve name and public key (for non-cert keys)
        // 2. Private key exponent as a bignum
        guard
            let curveName = buffer.readSSHString(),
            let _ = buffer.readSSHString(), // public key - we don't need it for reconstruction
            let privateKeyData = buffer.readSSHBignum()
        else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        guard curveName == "nistp384" else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        // Process the private key data to validate size and remove leading zero if present
        let keyData = try processECDSAPrivateKeyData(privateKeyData, expectedKeySize: 48)
        
        return try P384.Signing.PrivateKey(rawRepresentation: keyData)
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        let start = buffer.writerIndex
        
        // For ECDSA, the private key section contains:
        // 1. Curve name and public key (for non-cert keys)
        // 2. Private key exponent as a bignum
        writeECDSAPublicKey(to: &buffer, curveName: "nistp384", publicKeyData: publicKey.x963Representation)
        
        // Write private key as bignum - SSH bignum format preserves all bytes
        let privateKeyData = self.rawRepresentation
        buffer.writeInteger(UInt32(privateKeyData.count))
        buffer.writeBytes(privateKeyData)
        
        return buffer.writerIndex - start
    }
}

extension P521.Signing.PrivateKey: ByteBufferConvertible {
    public static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        // For ECDSA, the private key section contains:
        // 1. Curve name and public key (for non-cert keys)
        // 2. Private key exponent as a bignum
        guard
            let curveName = buffer.readSSHString(),
            let _ = buffer.readSSHString(), // public key - we don't need it for reconstruction
            let privateKeyData = buffer.readSSHBignum()
        else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        guard curveName == "nistp521" else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        // Process the private key data to validate size and remove leading zero if present
        let keyData = try processECDSAPrivateKeyData(privateKeyData, expectedKeySize: 66)
        
        return try P521.Signing.PrivateKey(rawRepresentation: keyData)
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        let start = buffer.writerIndex
        
        // For ECDSA, the private key section contains:
        // 1. Curve name and public key (for non-cert keys)
        // 2. Private key exponent as a bignum
        writeECDSAPublicKey(to: &buffer, curveName: "nistp521", publicKeyData: publicKey.x963Representation)
        
        // Write private key as bignum - SSH bignum format preserves all bytes
        let privateKeyData = self.rawRepresentation
        buffer.writeInteger(UInt32(privateKeyData.count))
        buffer.writeBytes(privateKeyData)
        
        return buffer.writerIndex - start
    }
}

// Public key types for ECDSA
extension P256.Signing.PublicKey: ByteBufferConvertible {
    public static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        // When called from OpenSSH.PrivateKey parsing, the key type has already been consumed
        // We expect to read curve name and EC point
        guard let curveName = buffer.readSSHString() else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        guard curveName == "nistp256" else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        // Then read the EC point data as SSH string (not buffer)
        guard let pointBytes = buffer.readSSHData() else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        guard pointBytes.first == uncompressedPointPrefix else { // Uncompressed point
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        return try P256.Signing.PublicKey(x963Representation: pointBytes)
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        return writeECDSAPublicKey(to: &buffer, curveName: "nistp256", publicKeyData: self.x963Representation)
    }
}

extension P384.Signing.PublicKey: ByteBufferConvertible {
    public static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        // When called from OpenSSH.PrivateKey parsing, the key type has already been consumed
        // We expect to read curve name and EC point
        guard let curveName = buffer.readSSHString() else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        guard curveName == "nistp384" else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        // Then read the EC point data as SSH string (not buffer)
        guard let pointBytes = buffer.readSSHData() else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        guard pointBytes.first == uncompressedPointPrefix else { // Uncompressed point
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        return try P384.Signing.PublicKey(x963Representation: pointBytes)
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        return writeECDSAPublicKey(to: &buffer, curveName: "nistp384", publicKeyData: self.x963Representation)
    }
}

extension P521.Signing.PublicKey: ByteBufferConvertible {
    public static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        // When called from OpenSSH.PrivateKey parsing, the key type has already been consumed
        // We expect to read curve name and EC point
        guard let curveName = buffer.readSSHString() else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        guard curveName == "nistp521" else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        // Then read the EC point data as SSH string (not buffer)
        guard let pointBytes = buffer.readSSHData() else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        guard pointBytes.first == uncompressedPointPrefix else { // Uncompressed point
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        return try P521.Signing.PublicKey(x963Representation: pointBytes)
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        return writeECDSAPublicKey(to: &buffer, curveName: "nistp521", publicKeyData: self.x963Representation)
    }
}

// OpenSSHPrivateKey conformances
extension P256.Signing.PrivateKey: OpenSSHPrivateKey {
    public typealias PublicKey = P256.Signing.PublicKey
    
    public static var publicKeyPrefix: String { "ecdsa-sha2-nistp256" }
    public static var privateKeyPrefix: String { "ecdsa-sha2-nistp256" }
    public static var keyType: OpenSSH.KeyType { .ecdsaP256 }
    public static var wrapPublicKeyInCompositeString: Bool { false }
    
    public func getPublicKey() -> P256.Signing.PublicKey {
        self.publicKey
    }
}

public extension P256.Signing.PrivateKey {
    /// Creates a new OpenSSH formatted private key
    /// - Parameters:
    ///   - comment: Optional comment to include in the key
    ///   - passphrase: Optional passphrase to encrypt the key
    ///   - cipher: Cipher to use for encryption (default: "none")
    ///   - rounds: Number of BCrypt rounds for key derivation (default: 16)
    /// - Returns: OpenSSH formatted private key string
    func makeSSHRepresentation(
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
}

extension P384.Signing.PrivateKey: OpenSSHPrivateKey {
    public typealias PublicKey = P384.Signing.PublicKey
    
    public static var publicKeyPrefix: String { "ecdsa-sha2-nistp384" }
    public static var privateKeyPrefix: String { "ecdsa-sha2-nistp384" }
    public static var keyType: OpenSSH.KeyType { .ecdsaP384 }
    public static var wrapPublicKeyInCompositeString: Bool { false }
    
    public func getPublicKey() -> P384.Signing.PublicKey {
        self.publicKey
    }
}

public extension P384.Signing.PrivateKey {
    /// Creates a new OpenSSH formatted private key
    /// - Parameters:
    ///   - comment: Optional comment to include in the key
    ///   - passphrase: Optional passphrase to encrypt the key
    ///   - cipher: Cipher to use for encryption (default: "none")
    ///   - rounds: Number of BCrypt rounds for key derivation (default: 16)
    /// - Returns: OpenSSH formatted private key string
    func makeSSHRepresentation(
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
}

extension P521.Signing.PrivateKey: OpenSSHPrivateKey {
    public typealias PublicKey = P521.Signing.PublicKey
    
    public static var publicKeyPrefix: String { "ecdsa-sha2-nistp521" }
    public static var privateKeyPrefix: String { "ecdsa-sha2-nistp521" }
    public static var keyType: OpenSSH.KeyType { .ecdsaP521 }
    public static var wrapPublicKeyInCompositeString: Bool { false }
    
    public func getPublicKey() -> P521.Signing.PublicKey {
        self.publicKey
    }
}

public extension P521.Signing.PrivateKey {
    /// Creates a new OpenSSH formatted private key
    /// - Parameters:
    ///   - comment: Optional comment to include in the key
    ///   - passphrase: Optional passphrase to encrypt the key
    ///   - cipher: Cipher to use for encryption (default: "none")
    ///   - rounds: Number of BCrypt rounds for key derivation (default: 16)
    /// - Returns: OpenSSH formatted private key string
    func makeSSHRepresentation(
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
}

// MARK: - PEM/PKCS#8 Support

// Note: Apple Crypto's P256, P384, and P521 types already have built-in support for PEM/PKCS#8 formats.
// The following documentation comments describe the existing functionality from Apple Crypto.

// MARK: P256 PEM/PKCS#8 Support

/*
 P256.Signing.PrivateKey already provides:
 - pemRepresentation: String - PEM representation using PKCS#8 format
 - init(pemRepresentation: String) - Creates from PEM string
 - derRepresentation: Data - DER representation using PKCS#8 format
 - init(derRepresentation: Data) - Creates from DER data
 
 P256.Signing.PublicKey already provides:
 - pemRepresentation: String - PEM representation using SubjectPublicKeyInfo format
 - init(pemRepresentation: String) - Creates from PEM string
 */

// MARK: P384 PEM/PKCS#8 Support

/*
 P384.Signing.PrivateKey already provides:
 - pemRepresentation: String - PEM representation using PKCS#8 format
 - init(pemRepresentation: String) - Creates from PEM string
 - derRepresentation: Data - DER representation using PKCS#8 format
 - init(derRepresentation: Data) - Creates from DER data
 
 P384.Signing.PublicKey already provides:
 - pemRepresentation: String - PEM representation using SubjectPublicKeyInfo format
 - init(pemRepresentation: String) - Creates from PEM string
 */

// MARK: P521 PEM/PKCS#8 Support

/*
 P521.Signing.PrivateKey already provides:
 - pemRepresentation: String - PEM representation using PKCS#8 format
 - init(pemRepresentation: String) - Creates from PEM string
 - derRepresentation: Data - DER representation using PKCS#8 format
 - init(derRepresentation: Data) - Creates from DER data
 
 P521.Signing.PublicKey already provides:
 - pemRepresentation: String - PEM representation using SubjectPublicKeyInfo format
 - init(pemRepresentation: String) - Creates from PEM string
 */