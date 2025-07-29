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
    // Check if we have the expected size with a leading zero byte
    if privateKeyData.count == expectedKeySize + 1 && privateKeyData[0] == 0 {
        // Remove the leading zero byte
        return privateKeyData.dropFirst()
    } else if privateKeyData.count == expectedKeySize {
        // Already the correct size
        return privateKeyData
    } else {
        // Invalid size
        throw InvalidOpenSSHKey.invalidLayout
    }
}

extension P256.Signing.PrivateKey: ByteBufferConvertible {
    public static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        guard
            let curveName = buffer.readSSHString(),
            let _ = buffer.readSSHBuffer(), // public key - we don't need it for reconstruction
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
        
        // Write curve name and public key
        writeECDSAPublicKey(to: &buffer, curveName: "nistp256", publicKeyData: publicKey.x963Representation)
        
        // Write private key as bignum (matching OpenSSH format)
        let privateKeyData = self.rawRepresentation
        let bignum = BigInt(privateKeyData)
        buffer.writeSSHBignum(bignum)
        
        return buffer.writerIndex - start
    }
}

extension P384.Signing.PrivateKey: ByteBufferConvertible {
    public static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        guard
            let curveName = buffer.readSSHString(),
            let _ = buffer.readSSHBuffer(), // public key - we don't need it for reconstruction
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
        
        // Write curve name and public key
        writeECDSAPublicKey(to: &buffer, curveName: "nistp384", publicKeyData: publicKey.x963Representation)
        
        // Write private key as bignum (matching OpenSSH format)
        let privateKeyData = self.rawRepresentation
        let bignum = BigInt(privateKeyData)
        buffer.writeSSHBignum(bignum)
        
        return buffer.writerIndex - start
    }
}

extension P521.Signing.PrivateKey: ByteBufferConvertible {
    public static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        guard
            let curveName = buffer.readSSHString(),
            let _ = buffer.readSSHBuffer(), // public key - we don't need it for reconstruction
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
        
        // Write curve name and public key
        writeECDSAPublicKey(to: &buffer, curveName: "nistp521", publicKeyData: publicKey.x963Representation)
        
        // Write private key as bignum (matching OpenSSH format)
        let privateKeyData = self.rawRepresentation
        let bignum = BigInt(privateKeyData)
        buffer.writeSSHBignum(bignum)
        
        return buffer.writerIndex - start
    }
}

// Public key types for ECDSA
extension P256.Signing.PublicKey: ByteBufferConvertible {
    public static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        // First read the curve name
        guard let curveName = buffer.readSSHString() else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        guard curveName == "nistp256" else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        // Then read the EC point data
        guard let pointData = buffer.readSSHBuffer() else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        let pointBytes = pointData.getBytes(at: 0, length: pointData.readableBytes) ?? []
        guard pointBytes.first == uncompressedPointPrefix else { // Uncompressed point
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        return try P256.Signing.PublicKey(x963Representation: pointBytes)
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        return writeECDSAPublicKey(to: &buffer, publicKeyData: self.x963Representation)
    }
}

extension P384.Signing.PublicKey: ByteBufferConvertible {
    public static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        // First read the curve name
        guard let curveName = buffer.readSSHString() else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        guard curveName == "nistp384" else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        // Then read the EC point data
        guard let pointData = buffer.readSSHBuffer() else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        let pointBytes = pointData.getBytes(at: 0, length: pointData.readableBytes) ?? []
        guard pointBytes.first == uncompressedPointPrefix else { // Uncompressed point
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        return try P384.Signing.PublicKey(x963Representation: pointBytes)
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        return writeECDSAPublicKey(to: &buffer, publicKeyData: self.x963Representation)
    }
}

extension P521.Signing.PublicKey: ByteBufferConvertible {
    public static func read(consuming buffer: inout ByteBuffer) throws -> Self {
        // First read the curve name
        guard let curveName = buffer.readSSHString() else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        guard curveName == "nistp521" else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        // Then read the EC point data
        guard let pointData = buffer.readSSHBuffer() else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        let pointBytes = pointData.getBytes(at: 0, length: pointData.readableBytes) ?? []
        guard pointBytes.first == uncompressedPointPrefix else { // Uncompressed point
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        return try P521.Signing.PublicKey(x963Representation: pointBytes)
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        return writeECDSAPublicKey(to: &buffer, publicKeyData: self.x963Representation)
    }
}

// OpenSSHPrivateKey conformances
extension P256.Signing.PrivateKey: OpenSSHPrivateKey {
    public typealias PublicKey = P256.Signing.PublicKey
    
    public static var publicKeyPrefix: String { "ecdsa-sha2-nistp256" }
    public static var privateKeyPrefix: String { "ecdsa-sha2-nistp256" }
    public static var keyType: OpenSSH.KeyType { .ecdsaP256 }
}

extension P384.Signing.PrivateKey: OpenSSHPrivateKey {
    public typealias PublicKey = P384.Signing.PublicKey
    
    public static var publicKeyPrefix: String { "ecdsa-sha2-nistp384" }
    public static var privateKeyPrefix: String { "ecdsa-sha2-nistp384" }
    public static var keyType: OpenSSH.KeyType { .ecdsaP384 }
}

extension P521.Signing.PrivateKey: OpenSSHPrivateKey {
    public typealias PublicKey = P521.Signing.PublicKey
    
    public static var publicKeyPrefix: String { "ecdsa-sha2-nistp521" }
    public static var privateKeyPrefix: String { "ecdsa-sha2-nistp521" }
    public static var keyType: OpenSSH.KeyType { .ecdsaP521 }
}