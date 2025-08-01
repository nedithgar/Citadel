import Foundation
import NIOSSH
import Crypto
import _CryptoExtras
import NIOCore

// MARK: - Signature Verification Extensions for NIOSSH Integration

extension NIOSSHCertifiedPublicKey {
    
    /// Extracts the signature algorithm from the certificate's signature blob
    /// This is useful for validating allowed signature algorithms
    public func extractSignatureAlgorithm() throws -> String? {
        // Note: NIOSSH doesn't directly expose the signature algorithm from the signature blob
        // This would require access to the raw signature data which is encapsulated in NIOSSHSignature
        // For now, we return nil as this information is not accessible
        return nil
    }
}

// MARK: - RSA Signature Algorithm Detection

// Note: NIOSSHPublicKey's internal structure is not accessible
// Key type detection would need to be done at a higher level

// MARK: - Signature Verification Helpers

/// Helper struct for working with SSH signatures
public struct SSHSignatureHelper {
    
    /// Parses the signature type from an SSH signature blob
    /// - Parameter signatureData: The raw signature data
    /// - Returns: The signature algorithm identifier, or nil if parsing fails
    public static func parseSignatureType(from signatureData: Data) -> String? {
        var buffer = ByteBuffer(bytes: signatureData)
        return buffer.readSSHString()
    }
    
    /// Validates RSA signature algorithms
    /// - Parameters:
    ///   - signatureType: The signature type to validate
    ///   - allowedAlgorithms: Set of allowed signature algorithms
    /// - Throws: SSHCertificateError if the algorithm is not allowed
    public static func validateRSASignatureAlgorithm(
        _ signatureType: String,
        allowedAlgorithms: Set<String>
    ) throws {
        // Check if this is an RSA signature
        let rsaAlgorithms = ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"]
        guard rsaAlgorithms.contains(signatureType) else {
            return // Not an RSA signature, no RSA-specific validation needed
        }
        
        // Validate against allowed algorithms
        guard allowedAlgorithms.contains(signatureType) else {
            throw SSHCertificateError.signatureAlgorithmNotAllowed(signatureType)
        }
    }
}

