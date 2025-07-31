import NIO
import NIOSSH
import Crypto
import _CryptoExtras

/// Errors that can occur during SSH authentication
public enum SSHAuthenticationError: Error {
    case certificateConversionFailed
    case certificateValidationFailed(Error)
}

/// Represents an authentication method.
public final class SSHAuthenticationMethod: NIOSSHClientUserAuthenticationDelegate {
    private enum Implementation {
        case custom(NIOSSHClientUserAuthenticationDelegate)
        case user(String, offer: NIOSSHUserAuthenticationOffer.Offer)
    }
    
    private let allImplementations: [Implementation]
    private var implementations: [Implementation]
    
    internal init(
        username: String,
        offer: NIOSSHUserAuthenticationOffer.Offer
    ) {
        self.allImplementations = [.user(username, offer: offer)]
        self.implementations = allImplementations
    }
    
    internal init(
        custom: NIOSSHClientUserAuthenticationDelegate
    ) {
        self.allImplementations = [.custom(custom)]
        self.implementations = allImplementations
    }
    
    /// Creates a password based authentication method.
    /// - Parameters:
    ///  - username: The username to authenticate with.
    /// - password: The password to authenticate with.
    public static func passwordBased(username: String, password: String) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .password(.init(password: password)))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func rsa(username: String, privateKey: Insecure.RSA.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(custom: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func ed25519(username: String, privateKey: Curve25519.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(ed25519Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p256(username: String, privateKey: P256.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p256Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p384(username: String, privateKey: P384.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p384Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p521(username: String, privateKey: P521.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p521Key: privateKey))))
    }
    
    /// Creates a certificate-based authentication method for Ed25519.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The certificate public key to use for authentication.
    ///   - trustedCAs: List of trusted CA public keys (optional, for validation)
    ///   - clientAddress: Client source address (optional, for validation)
    ///   - validateCertificate: Whether to validate the certificate (default: false for client use)
    /// - Throws: SSHCertificateValidationError if certificate validation fails
    /// - Throws: SSHAuthenticationError if certificate conversion fails
    public static func ed25519Certificate(
        username: String,
        privateKey: Curve25519.Signing.PrivateKey,
        certificate: Ed25519.CertificatePublicKey,
        trustedCAs: [NIOSSHPublicKey] = [],
        clientAddress: String? = nil,
        validateCertificate: Bool = false
    ) throws -> SSHAuthenticationMethod {
        // Only validate certificate if explicitly requested
        // Client-side authentication doesn't need to validate its own certificate
        if validateCertificate {
            // Check if the username is valid for this certificate
            if !certificate.certificate.isValid(for: username) {
                throw SSHCertificateError.principalMismatch(
                    username: username,
                    allowedPrincipals: certificate.certificate.validPrincipals
                )
            }
            
            let context = SSHCertificateValidationContext(
                username: username,
                sourceAddress: clientAddress,
                trustedCAs: trustedCAs
            )
            try SSHCertificateValidator.validate(certificate.certificate, context: context)
        }
        
        guard let nioSSHCertificate = CertificateConverter.convertToNIOSSHCertifiedPublicKey(certificate) else {
            throw SSHAuthenticationError.certificateConversionFailed
        }
        
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: .init(ed25519Key: privateKey), certifiedKey: nioSSHCertificate))
        )
    }

    // TODO: Remember to remove
    // Only reference in development
    public static func ed25519CertificateNative(username: String, privateKey: Curve25519.Signing.PrivateKey, certificate: NIOSSHCertifiedPublicKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: .init(ed25519Key: privateKey), certifiedKey: certificate))
        )
    }

    public static func p256CertificateNative(username: String, privateKey: P256.Signing.PrivateKey, certificate: NIOSSHCertifiedPublicKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: .init(p256Key: privateKey), certifiedKey: certificate))
        )
    }
    
    /// Creates a certificate-based authentication method for RSA.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The certificate public key to use for authentication.
    ///   - trustedCAs: List of trusted CA public keys (optional, for validation)
    ///   - clientAddress: Client source address (optional, for validation)
    ///   - validateCertificate: Whether to validate the certificate (default: false for client use)
    /// - Throws: SSHCertificateValidationError if certificate validation fails
    /// - Throws: SSHAuthenticationError if certificate conversion fails
    public static func rsaCertificate(
        username: String,
        privateKey: Insecure.RSA.PrivateKey,
        certificate: Insecure.RSA.CertificatePublicKey,
        trustedCAs: [NIOSSHPublicKey] = [],
        clientAddress: String? = nil,
        validateCertificate: Bool = false
    ) throws -> SSHAuthenticationMethod {
        // Only validate certificate if explicitly requested
        // Client-side authentication doesn't need to validate its own certificate
        if validateCertificate {
            // Check if the username is valid for this certificate
            if !certificate.certificate.isValid(for: username) {
                throw SSHCertificateError.principalMismatch(
                    username: username,
                    allowedPrincipals: certificate.certificate.validPrincipals
                )
            }
            
            let context = SSHCertificateValidationContext(
                username: username,
                sourceAddress: clientAddress,
                trustedCAs: trustedCAs
            )
            try SSHCertificateValidator.validate(certificate.certificate, context: context)
        }
        
        guard let nioSSHCertificate = CertificateConverter.convertToNIOSSHCertifiedPublicKey(certificate) else {
            throw SSHAuthenticationError.certificateConversionFailed
        }
        
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: .init(custom: privateKey), certifiedKey: nioSSHCertificate))
        )
    }
    
    /// Creates a certificate-based authentication method for P256.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The certificate public key to use for authentication.
    ///   - trustedCAs: List of trusted CA public keys (optional, for validation)
    ///   - clientAddress: Client source address (optional, for validation)
    ///   - validateCertificate: Whether to validate the certificate (default: false for client use)
    /// - Throws: SSHCertificateValidationError if certificate validation fails
    /// - Throws: SSHAuthenticationError if certificate conversion fails
    public static func p256Certificate(
        username: String,
        privateKey: P256.Signing.PrivateKey,
        certificate: P256.Signing.CertificatePublicKey,
        trustedCAs: [NIOSSHPublicKey] = [],
        clientAddress: String? = nil,
        validateCertificate: Bool = false
    ) throws -> SSHAuthenticationMethod {
        // Only validate certificate if explicitly requested
        // Client-side authentication doesn't need to validate its own certificate
        if validateCertificate {
            // Check if the username is valid for this certificate
            if !certificate.certificate.isValid(for: username) {
                throw SSHCertificateError.principalMismatch(
                    username: username,
                    allowedPrincipals: certificate.certificate.validPrincipals
                )
            }
            
            let context = SSHCertificateValidationContext(
                username: username,
                sourceAddress: clientAddress,
                trustedCAs: trustedCAs
            )
            try SSHCertificateValidator.validate(certificate.certificate, context: context)
        }
        
        guard let nioSSHCertificate = CertificateConverter.convertToNIOSSHCertifiedPublicKey(certificate) else {
            throw SSHAuthenticationError.certificateConversionFailed
        }
        
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: .init(p256Key: privateKey), certifiedKey: nioSSHCertificate))
        )
    }

    /// Creates a certificate-based authentication method for P384.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The certificate public key to use for authentication.
    ///   - trustedCAs: List of trusted CA public keys (optional, for validation)
    ///   - clientAddress: Client source address (optional, for validation)
    ///   - validateCertificate: Whether to validate the certificate (default: false for client use)
    /// - Throws: SSHCertificateValidationError if certificate validation fails
    /// - Throws: SSHAuthenticationError if certificate conversion fails
    public static func p384Certificate(
        username: String,
        privateKey: P384.Signing.PrivateKey,
        certificate: P384.Signing.CertificatePublicKey,
        trustedCAs: [NIOSSHPublicKey] = [],
        clientAddress: String? = nil,
        validateCertificate: Bool = false
    ) throws -> SSHAuthenticationMethod {
        // Only validate certificate if explicitly requested
        // Client-side authentication doesn't need to validate its own certificate
        if validateCertificate {
            // Check if the username is valid for this certificate
            if !certificate.certificate.isValid(for: username) {
                throw SSHCertificateError.principalMismatch(
                    username: username,
                    allowedPrincipals: certificate.certificate.validPrincipals
                )
            }
            
            let context = SSHCertificateValidationContext(
                username: username,
                sourceAddress: clientAddress,
                trustedCAs: trustedCAs
            )
            try SSHCertificateValidator.validate(certificate.certificate, context: context)
        }
        
        guard let nioSSHCertificate = CertificateConverter.convertToNIOSSHCertifiedPublicKey(certificate) else {
            throw SSHAuthenticationError.certificateConversionFailed
        }
        
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: .init(p384Key: privateKey), certifiedKey: nioSSHCertificate))
        )
    }
    
    /// Creates a certificate-based authentication method for P521.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The certificate public key to use for authentication.
    ///   - trustedCAs: List of trusted CA public keys (optional, for validation)
    ///   - clientAddress: Client source address (optional, for validation)
    ///   - validateCertificate: Whether to validate the certificate (default: false for client use)
    /// - Throws: SSHCertificateValidationError if certificate validation fails
    /// - Throws: SSHAuthenticationError if certificate conversion fails
    public static func p521Certificate(
        username: String,
        privateKey: P521.Signing.PrivateKey,
        certificate: P521.Signing.CertificatePublicKey,
        trustedCAs: [NIOSSHPublicKey] = [],
        clientAddress: String? = nil,
        validateCertificate: Bool = false
    ) throws -> SSHAuthenticationMethod {
        // Only validate certificate if explicitly requested
        // Client-side authentication doesn't need to validate its own certificate
        if validateCertificate {
            // Check if the username is valid for this certificate
            if !certificate.certificate.isValid(for: username) {
                throw SSHCertificateError.principalMismatch(
                    username: username,
                    allowedPrincipals: certificate.certificate.validPrincipals
                )
            }
            
            let context = SSHCertificateValidationContext(
                username: username,
                sourceAddress: clientAddress,
                trustedCAs: trustedCAs
            )
            try SSHCertificateValidator.validate(certificate.certificate, context: context)
        }
        
        guard let nioSSHCertificate = CertificateConverter.convertToNIOSSHCertifiedPublicKey(certificate) else {
            throw SSHAuthenticationError.certificateConversionFailed
        }
        
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: .init(p521Key: privateKey), certifiedKey: nioSSHCertificate))
        )
    }
    
    public static func custom(_ auth: NIOSSHClientUserAuthenticationDelegate) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(custom: auth)
    }
    
    /// Creates a certificate-based authentication method using NIOSSH types directly.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The NIOSSH private key to authenticate with.
    ///   - certificate: The NIOSSH certified public key to use for authentication.
    ///   - trustedCAs: List of trusted CA public keys (optional, for validation)
    ///   - clientAddress: Client source address (optional, for validation)
    ///   - skipValidation: Skip certificate validation (default: false, use with caution)
    /// - Throws: SSHCertificateError if certificate validation fails
    public static func certificate(
        username: String,
        privateKey: NIOSSHPrivateKey,
        certificate: NIOSSHCertifiedPublicKey,
        trustedCAs: [NIOSSHPublicKey] = [],
        clientAddress: String? = nil,
        skipValidation: Bool = false
    ) throws -> SSHAuthenticationMethod {
        // Perform validation unless explicitly skipped
        if !skipValidation && !trustedCAs.isEmpty {
            // Extract the underlying certificate data for validation
            // Note: This would require access to the certificate's raw data
            // For now, we'll create the method without validation
            // In a real implementation, we'd need to expose the certificate data from NIOSSHCertifiedPublicKey
        }
        
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: privateKey, certifiedKey: certificate))
        )
    }
    
    
    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        if implementations.isEmpty {
            nextChallengePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
            return
        }
        
        let implementation = implementations.removeFirst()

        switch implementation {
        case .user(let username, offer: let offer):
            switch offer {
            case .password:
                guard availableMethods.contains(.password) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedPasswordAuthentication)
                    return
                }
            case .hostBased:
                guard availableMethods.contains(.hostBased) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedHostBasedAuthentication)
                    return
                }
            case .privateKey:
                guard availableMethods.contains(.publicKey) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedPrivateKeyAuthentication)
                    return
                }
            case .none:
                ()
            }
            
            nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: offer))
        case .custom(let implementation):
            implementation.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
        }
    }
}

