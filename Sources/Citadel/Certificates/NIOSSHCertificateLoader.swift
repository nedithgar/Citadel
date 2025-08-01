import Foundation
import NIOSSH
import NIOCore

/// Errors that can occur during NIOSSH certificate loading
public enum NIOSSHCertificateLoadingError: Error {
    case invalidFormat
    case notACertificate
    case unsupportedCertificateType
}

/// Utilities for loading SSH certificates using NIOSSH types.
public enum NIOSSHCertificateLoader {
    
    /// Loads a certificate from an OpenSSH format file (e.g., id_ed25519-cert.pub).
    /// - Parameter path: The path to the OpenSSH format certificate file
    /// - Returns: The parsed certificate as NIOSSHCertifiedPublicKey
    /// - Throws: An error if the file cannot be read or parsed
    public static func loadFromOpenSSHFile(at path: String) throws -> NIOSSHCertifiedPublicKey {
        let content = try String(contentsOfFile: path, encoding: .utf8)
        return try loadFromOpenSSHString(content)
    }
    
    /// Loads a certificate from an OpenSSH format string.
    /// - Parameter openSSHString: The OpenSSH format string (e.g., "ssh-ed25519-cert-v01@openssh.com BASE64DATA comment")
    /// - Returns: The parsed certificate as NIOSSHCertifiedPublicKey
    /// - Throws: An error if the string cannot be parsed
    public static func loadFromOpenSSHString(_ openSSHString: String) throws -> NIOSSHCertifiedPublicKey {
        let trimmed = openSSHString.trimmingCharacters(in: .whitespacesAndNewlines)
        
        // Parse as NIOSSHPublicKey first
        let publicKey = try NIOSSHPublicKey(openSSHPublicKey: trimmed)
        
        // Extract the certified key
        guard let certifiedKey = NIOSSHCertifiedPublicKey(publicKey) else {
            throw NIOSSHCertificateLoadingError.notACertificate
        }
        
        return certifiedKey
    }
    
    /// Loads a certificate from binary data.
    /// - Parameter data: The binary certificate data
    /// - Returns: The parsed certificate as NIOSSHCertifiedPublicKey
    /// - Throws: An error if the data cannot be parsed
    public static func loadFromBinaryData(_ data: Data) throws -> NIOSSHCertifiedPublicKey {
        var buffer = ByteBufferAllocator().buffer(capacity: data.count)
        buffer.writeBytes(data)
        
        // Read the key type prefix
        guard let keyTypeLength = buffer.getInteger(at: buffer.readerIndex, as: UInt32.self),
              let keyTypeData = buffer.getBytes(at: buffer.readerIndex + 4, length: Int(keyTypeLength)),
              let keyType = String(data: Data(keyTypeData), encoding: .utf8) else {
            throw NIOSSHCertificateLoadingError.invalidFormat
        }
        
        // Check if it's a certificate type
        guard keyType.hasSuffix("-cert-v01@openssh.com") else {
            throw NIOSSHCertificateLoadingError.notACertificate
        }
        
        // Convert to base64 and parse as OpenSSH format
        let base64String = data.base64EncodedString()
        let openSSHString = "\(keyType) \(base64String)"
        
        return try loadFromOpenSSHString(openSSHString)
    }
    
    /// Loads multiple certificates from a file containing one certificate per line.
    /// - Parameter path: The path to the file
    /// - Returns: An array of parsed certificates
    /// - Throws: An error if the file cannot be read
    public static func loadMultipleFromFile(at path: String) throws -> [NIOSSHCertifiedPublicKey] {
        let content = try String(contentsOfFile: path, encoding: .utf8)
        let lines = content.components(separatedBy: .newlines)
        
        return lines.compactMap { line in
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { return nil }
            return try? loadFromOpenSSHString(trimmed)
        }
    }
    
}