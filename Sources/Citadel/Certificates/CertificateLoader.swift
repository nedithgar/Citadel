import Foundation
import NIOSSH
import NIO
import Crypto
import _CryptoExtras

/// Errors that can occur during certificate loading
public enum CertificateLoadingError: Error {
    case unsupportedKeyType
    case unsupportedOperation(String)
    case invalidCertificateData
    case keyMismatch
}

/// Utilities for loading SSH certificates from files or data.
public enum CertificateLoader {
    
    /// Loads a certificate from an OpenSSH format file (e.g., id_ed25519-cert.pub).
    /// - Parameters:
    ///   - path: The path to the OpenSSH format certificate file (typically ends with -cert.pub).
    /// - Returns: The parsed certificate as NIOSSHPublicKeyProtocol.
    /// - Throws: An error if the file cannot be read or parsed.
    /// - Note: This method expects OpenSSH text format: `ssh-xxx-cert-v01@openssh.com BASE64DATA comment`
    public static func loadCertificateFromOpenSSHFile(from path: String) throws -> NIOSSHPublicKeyProtocol {
        let certificateString = try String(contentsOfFile: path, encoding: .utf8)
        
        // Parse the OpenSSH format (splits by whitespace)
        let parts = certificateString.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ")
        
        guard parts.count >= 2 else {
            throw CertificateLoadingError.invalidCertificateData
        }
        
        // The second part is the base64-encoded certificate data
        guard let certificateData = Data(base64Encoded: String(parts[1])) else {
            throw CertificateLoadingError.invalidCertificateData
        }
        
        // Parse the binary certificate data
        return try loadCertificateFromBinary(data: certificateData)
    }
    
    
    /// Loads a certificate from a file containing raw binary certificate data.
    /// - Parameters:
    ///   - path: The path to the file containing raw binary certificate data.
    /// - Returns: The parsed certificate as NIOSSHPublicKeyProtocol.
    /// - Throws: An error if the file cannot be read or parsed.
    /// - Warning: This method expects raw binary data, NOT OpenSSH text format. Use `loadCertificateFromOpenSSHFile` for .pub files.
    public static func loadCertificateFromBinaryFile(from path: String) throws -> NIOSSHPublicKeyProtocol {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)
        return try loadCertificateFromBinary(data: data)
    }
    
    
    /// Loads a certificate from raw binary data.
    /// - Parameters:
    ///   - data: The raw binary certificate data (NOT base64 encoded).
    /// - Returns: The parsed certificate as NIOSSHPublicKeyProtocol.
    /// - Throws: An error if the data cannot be parsed.
    /// - Note: This expects the decoded binary format, not OpenSSH text format or base64.
    public static func loadCertificateFromBinary(data: Data) throws -> NIOSSHPublicKeyProtocol {
        // Parse the certificate data directly
        var buffer = ByteBufferAllocator().buffer(capacity: data.count)
        buffer.writeBytes(data)
        
        // Try each certificate type
        if let cert = try? Ed25519.CertificatePublicKey.read(from: &buffer) {
            return cert
        }
        
        buffer.moveReaderIndex(to: 0)
        if let cert = try? Insecure.RSA.CertificatePublicKey.read(from: &buffer) {
            return cert
        }
        
        buffer.moveReaderIndex(to: 0)
        if let cert = try? P256.Signing.CertificatePublicKey.read(from: &buffer) {
            return cert
        }
        
        buffer.moveReaderIndex(to: 0)
        if let cert = try? P384.Signing.CertificatePublicKey.read(from: &buffer) {
            return cert
        }
        
        buffer.moveReaderIndex(to: 0)
        if let cert = try? P521.Signing.CertificatePublicKey.read(from: &buffer) {
            return cert
        }
        
        throw CertificateLoadingError.unsupportedKeyType
    }
    
}