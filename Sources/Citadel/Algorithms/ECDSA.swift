import Foundation
import Crypto
import _CryptoExtras
import NIOCore
import BigInt

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
        
        // ECDSA private keys are stored as bignums in OpenSSH format
        // P256 private keys should be exactly 32 bytes (may have leading zero)
        guard privateKeyData.count >= 32 && privateKeyData.count <= 33 else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        // Remove leading zero if present
        let keyData = privateKeyData.count == 33 && privateKeyData[0] == 0 ? 
            privateKeyData.dropFirst() : privateKeyData
        
        return try P256.Signing.PrivateKey(rawRepresentation: keyData)
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        let start = buffer.writerIndex
        buffer.writeSSHString("nistp256")
        
        let publicKey = self.publicKey
        var publicKeyBuffer = ByteBuffer()
        publicKeyBuffer.writeBytes(publicKey.x963Representation)
        buffer.writeSSHString(&publicKeyBuffer)
        
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
        
        // ECDSA private keys are stored as bignums in OpenSSH format
        // P384 private keys should be exactly 48 bytes (may have leading zero)
        guard privateKeyData.count >= 48 && privateKeyData.count <= 49 else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        // Remove leading zero if present
        let keyData = privateKeyData.count == 49 && privateKeyData[0] == 0 ? 
            privateKeyData.dropFirst() : privateKeyData
        
        return try P384.Signing.PrivateKey(rawRepresentation: Data(keyData))
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        let start = buffer.writerIndex
        buffer.writeSSHString("nistp384")
        
        let publicKey = self.publicKey
        var publicKeyBuffer = ByteBuffer()
        publicKeyBuffer.writeBytes(publicKey.x963Representation)
        buffer.writeSSHString(&publicKeyBuffer)
        
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
        
        // ECDSA private keys are stored as bignums in OpenSSH format
        // P521 private keys should be exactly 66 bytes (may have leading zero)
        guard privateKeyData.count >= 66 && privateKeyData.count <= 67 else {
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        // Remove leading zero if present
        let keyData = privateKeyData.count == 67 && privateKeyData[0] == 0 ? 
            privateKeyData.dropFirst() : privateKeyData
        
        return try P521.Signing.PrivateKey(rawRepresentation: Data(keyData))
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        let start = buffer.writerIndex
        buffer.writeSSHString("nistp521")
        
        let publicKey = self.publicKey
        var publicKeyBuffer = ByteBuffer()
        publicKeyBuffer.writeBytes(publicKey.x963Representation)
        buffer.writeSSHString(&publicKeyBuffer)
        
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
        guard pointBytes.first == 0x04 else { // Uncompressed point
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        return try P256.Signing.PublicKey(x963Representation: pointBytes)
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        let start = buffer.writerIndex
        var publicKeyBuffer = ByteBuffer()
        publicKeyBuffer.writeBytes(self.x963Representation)
        buffer.writeSSHString(&publicKeyBuffer)
        return buffer.writerIndex - start
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
        guard pointBytes.first == 0x04 else { // Uncompressed point
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        return try P384.Signing.PublicKey(x963Representation: pointBytes)
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        let start = buffer.writerIndex
        var publicKeyBuffer = ByteBuffer()
        publicKeyBuffer.writeBytes(self.x963Representation)
        buffer.writeSSHString(&publicKeyBuffer)
        return buffer.writerIndex - start
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
        guard pointBytes.first == 0x04 else { // Uncompressed point
            throw InvalidOpenSSHKey.invalidLayout
        }
        
        return try P521.Signing.PublicKey(x963Representation: pointBytes)
    }
    
    public func write(to buffer: inout ByteBuffer) -> Int {
        let start = buffer.writerIndex
        var publicKeyBuffer = ByteBuffer()
        publicKeyBuffer.writeBytes(self.x963Representation)
        buffer.writeSSHString(&publicKeyBuffer)
        return buffer.writerIndex - start
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