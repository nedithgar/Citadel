import Foundation
import NIOSSH
import Crypto
import _CryptoExtras

// MARK: - Certificate-based Authentication Methods using NIOSSH

extension SSHAuthenticationMethod {
    
    /// Creates a new SSH user authentication request using Ed25519 private key with certificate.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The NIOSSH certificate to use for authentication.
    ///   - trustedCAs: List of trusted CA public keys (optional, for validation)
    ///   - clientAddress: Client source address (optional, for validation)
    ///   - validateCertificate: Whether to validate the certificate (default: false for client use)
    /// - Throws: SSHCertificateError if certificate validation fails
    public static func ed25519Certificate(
        username: String,
        privateKey: Curve25519.Signing.PrivateKey,
        certificate: NIOSSHCertifiedPublicKey,
        trustedCAs: [NIOSSHPublicKey] = [],
        clientAddress: String? = nil,
        validateCertificate: Bool = false
    ) throws -> SSHAuthenticationMethod {
        
        if validateCertificate {
            _ = try certificate.validateForAuthentication(
                username: username,
                sourceAddress: clientAddress
            )
            
            // Validate against trusted CAs if provided
            if !trustedCAs.isEmpty {
                try validateCertificateCA(certificate, trustedCAs: trustedCAs, principal: username)
            }
        }
        
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: .init(ed25519Key: privateKey), certifiedKey: certificate))
        )
    }
    
    /// Creates a new SSH user authentication request using RSA private key with certificate.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The NIOSSH certificate to use for authentication.
    ///   - trustedCAs: List of trusted CA public keys (optional, for validation)
    ///   - clientAddress: Client source address (optional, for validation)
    ///   - validateCertificate: Whether to validate the certificate (default: false for client use)
    /// - Throws: SSHCertificateError if certificate validation fails
    public static func rsaCertificate(
        username: String,
        privateKey: Insecure.RSA.PrivateKey,
        certificate: NIOSSHCertifiedPublicKey,
        trustedCAs: [NIOSSHPublicKey] = [],
        clientAddress: String? = nil,
        validateCertificate: Bool = false
    ) throws -> SSHAuthenticationMethod {
        
        if validateCertificate {
            _ = try certificate.validateForAuthentication(
                username: username,
                sourceAddress: clientAddress
            )
            
            // Validate against trusted CAs if provided
            if !trustedCAs.isEmpty {
                try validateCertificateCA(certificate, trustedCAs: trustedCAs, principal: username)
            }
        }
        
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: .init(custom: privateKey), certifiedKey: certificate))
        )
    }
    
    /// Creates a new SSH user authentication request using P256 private key with certificate.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The NIOSSH certificate to use for authentication.
    ///   - trustedCAs: List of trusted CA public keys (optional, for validation)
    ///   - clientAddress: Client source address (optional, for validation)
    ///   - validateCertificate: Whether to validate the certificate (default: false for client use)
    /// - Throws: SSHCertificateError if certificate validation fails
    public static func p256Certificate(
        username: String,
        privateKey: P256.Signing.PrivateKey,
        certificate: NIOSSHCertifiedPublicKey,
        trustedCAs: [NIOSSHPublicKey] = [],
        clientAddress: String? = nil,
        validateCertificate: Bool = false
    ) throws -> SSHAuthenticationMethod {
        
        if validateCertificate {
            _ = try certificate.validateForAuthentication(
                username: username,
                sourceAddress: clientAddress
            )
            
            // Validate against trusted CAs if provided
            if !trustedCAs.isEmpty {
                try validateCertificateCA(certificate, trustedCAs: trustedCAs, principal: username)
            }
        }
        
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: .init(p256Key: privateKey), certifiedKey: certificate))
        )
    }
    
    /// Creates a new SSH user authentication request using P384 private key with certificate.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The NIOSSH certificate to use for authentication.
    ///   - trustedCAs: List of trusted CA public keys (optional, for validation)
    ///   - clientAddress: Client source address (optional, for validation)
    ///   - validateCertificate: Whether to validate the certificate (default: false for client use)
    /// - Throws: SSHCertificateError if certificate validation fails
    public static func p384Certificate(
        username: String,
        privateKey: P384.Signing.PrivateKey,
        certificate: NIOSSHCertifiedPublicKey,
        trustedCAs: [NIOSSHPublicKey] = [],
        clientAddress: String? = nil,
        validateCertificate: Bool = false
    ) throws -> SSHAuthenticationMethod {
        
        if validateCertificate {
            _ = try certificate.validateForAuthentication(
                username: username,
                sourceAddress: clientAddress
            )
            
            // Validate against trusted CAs if provided
            if !trustedCAs.isEmpty {
                try validateCertificateCA(certificate, trustedCAs: trustedCAs, principal: username)
            }
        }
        
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: .init(p384Key: privateKey), certifiedKey: certificate))
        )
    }
    
    /// Creates a new SSH user authentication request using P521 private key with certificate.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The NIOSSH certificate to use for authentication.
    ///   - trustedCAs: List of trusted CA public keys (optional, for validation)
    ///   - clientAddress: Client source address (optional, for validation)
    ///   - validateCertificate: Whether to validate the certificate (default: false for client use)
    /// - Throws: SSHCertificateError if certificate validation fails
    public static func p521Certificate(
        username: String,
        privateKey: P521.Signing.PrivateKey,
        certificate: NIOSSHCertifiedPublicKey,
        trustedCAs: [NIOSSHPublicKey] = [],
        clientAddress: String? = nil,
        validateCertificate: Bool = false
    ) throws -> SSHAuthenticationMethod {
        
        if validateCertificate {
            _ = try certificate.validateForAuthentication(
                username: username,
                sourceAddress: clientAddress
            )
            
            // Validate against trusted CAs if provided
            if !trustedCAs.isEmpty {
                try validateCertificateCA(certificate, trustedCAs: trustedCAs, principal: username)
            }
        }
        
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: .init(p521Key: privateKey), certifiedKey: certificate))
        )
    }
    
    // MARK: - Helper Methods
    
    /// Validates a certificate against trusted CAs
    private static func validateCertificateCA(
        _ certificate: NIOSSHCertifiedPublicKey,
        trustedCAs: [NIOSSHPublicKey],
        principal: String
    ) throws {
        var isValid = false
        for ca in trustedCAs {
            do {
                try certificate.validate(
                    principal: principal,
                    type: .user,
                    allowedAuthoritySigningKeys: [ca]
                )
                isValid = true
                break
            } catch {
                continue
            }
        }
        if !isValid {
            throw SSHCertificateError.untrustedCA
        }
    }
}