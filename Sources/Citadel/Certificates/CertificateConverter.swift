import Foundation
import NIOSSH
import NIO
import Crypto
import _CryptoExtras

/// Utilities for converting between Citadel certificate types and NIOSSH types.
public enum CertificateConverter {
    
    /// Converts a Citadel certificate type to NIOSSHPublicKey containing a certified key.
    /// - Parameter certificate: The certificate implementing NIOSSHPublicKeyProtocol
    /// - Returns: A NIOSSHPublicKey containing the certificate, or nil if conversion fails
    public static func convertToNIOSSHPublicKey(_ certificate: NIOSSHPublicKeyProtocol) -> NIOSSHPublicKey? {
        // For ECDSA certificates, use the specialized builder
        let data: Data?
        let prefix: String
        
        switch certificate {
        case let p256Cert as P256.Signing.CertificatePublicKey:
            data = ECDSACertificateBuilder.buildP256Certificate(from: p256Cert)
            prefix = P256.Signing.CertificatePublicKey.publicKeyPrefix
        case let p384Cert as P384.Signing.CertificatePublicKey:
            data = ECDSACertificateBuilder.buildP384Certificate(from: p384Cert)
            prefix = P384.Signing.CertificatePublicKey.publicKeyPrefix
        case let p521Cert as P521.Signing.CertificatePublicKey:
            data = ECDSACertificateBuilder.buildP521Certificate(from: p521Cert)
            prefix = P521.Signing.CertificatePublicKey.publicKeyPrefix
        case is Ed25519.CertificatePublicKey:
            // Ed25519 works with the standard approach
            var buffer = ByteBufferAllocator().buffer(capacity: 4096)
            _ = certificate.write(to: &buffer)
            data = Data(buffer.readableBytesView)
            prefix = Ed25519.CertificatePublicKey.publicKeyPrefix
        case is Insecure.RSA.CertificatePublicKey:
            // NIOSSH doesn't support RSA certificates
            return nil
        default:
            return nil
        }
        
        guard let certData = data else {
            return nil
        }
        
        let base64 = certData.base64EncodedString()
        let openSSHString = "\(prefix) \(base64)"
        
        // Try to parse as OpenSSH public key
        do {
            return try NIOSSHPublicKey(openSSHPublicKey: openSSHString)
        } catch {
            return nil
        }
    }
    
    /// Converts a Citadel certificate to NIOSSHCertifiedPublicKey if possible.
    /// - Parameter certificate: The certificate implementing NIOSSHPublicKeyProtocol
    /// - Returns: A NIOSSHCertifiedPublicKey, or nil if the certificate cannot be converted
    public static func convertToNIOSSHCertifiedPublicKey(_ certificate: NIOSSHPublicKeyProtocol) -> NIOSSHCertifiedPublicKey? {
        guard let publicKey = convertToNIOSSHPublicKey(certificate) else {
            return nil
        }
        return NIOSSHCertifiedPublicKey(publicKey)
    }
    
    /// Creates a NIOSSHPublicKey from certificate data in OpenSSH format.
    /// - Parameter data: The certificate data (e.g., contents of a -cert.pub file)
    /// - Returns: A NIOSSHPublicKey containing the certificate
    /// - Throws: An error if the data is not a valid OpenSSH certificate
    public static func createFromOpenSSHData(_ data: Data) throws -> NIOSSHPublicKey {
        let string = String(data: data, encoding: .utf8) ?? ""
        return try NIOSSHPublicKey(openSSHPublicKey: string.trimmingCharacters(in: .whitespacesAndNewlines))
    }
}