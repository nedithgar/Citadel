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
    
    /// Loads a certificate from a file path.
    /// - Parameters:
    ///   - path: The path to the certificate file (typically ends with -cert.pub).
    /// - Returns: The parsed certificate as NIOSSHPublicKeyProtocol.
    /// - Throws: An error if the file cannot be read or parsed.
    public static func loadCertificate(from path: String) throws -> NIOSSHPublicKeyProtocol {
        let url = URL(fileURLWithPath: path)
        let data = try Data(contentsOf: url)
        return try loadCertificate(from: data)
    }
    
    /// Loads a certificate from data.
    /// - Parameters:
    ///   - data: The certificate data.
    /// - Returns: The parsed certificate as NIOSSHPublicKeyProtocol.
    /// - Throws: An error if the data cannot be parsed.
    public static func loadCertificate(from data: Data) throws -> NIOSSHPublicKeyProtocol {
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