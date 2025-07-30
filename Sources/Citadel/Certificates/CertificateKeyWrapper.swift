import Foundation
import NIOSSH
import NIO
import Crypto
import _CryptoExtras

/// Provides utilities to convert Citadel certificate types to NIOSSHCertifiedPublicKey
/// 
/// This is a temporary approach that uses the certificate types directly as NIOSSHPublicKeyProtocol implementations.
/// The certificate authentication in SSH works by:
/// 1. The certificate types (Ed25519.CertificatePublicKey, etc.) already implement NIOSSHPublicKeyProtocol
/// 2. These can be wrapped in NIOSSHPublicKey using the .custom case
/// 3. During authentication, the certificate data is sent along with the signature
public enum CertificateKeyWrapper {
    
    /// Helper method to check if a key type represents a certificate
    public static func isCertificateKeyType(_ keyType: NIOSSHPublicKeyProtocol.Type) -> Bool {
        return keyType == Ed25519.CertificatePublicKey.self ||
               keyType == Insecure.RSA.CertificatePublicKey.self ||
               keyType == P256.Signing.CertificatePublicKey.self ||
               keyType == P384.Signing.CertificatePublicKey.self ||
               keyType == P521.Signing.CertificatePublicKey.self
    }
}