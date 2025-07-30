import NIO
import NIOSSH
import Crypto
import _CryptoExtras

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
    public static func ed25519Certificate(username: String, privateKey: Curve25519.Signing.PrivateKey, certificate: Ed25519.CertificatePublicKey) -> SSHAuthenticationMethod {
        let delegate = CertificateAuthenticationDelegate(
            username: username,
            privateKey: .init(ed25519Key: privateKey),
            certificate: certificate
        )
        return SSHAuthenticationMethod(custom: delegate)
    }
    
    /// Creates a certificate-based authentication method for RSA.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The certificate public key to use for authentication.
    public static func rsaCertificate(username: String, privateKey: Insecure.RSA.PrivateKey, certificate: Insecure.RSA.CertificatePublicKey) -> SSHAuthenticationMethod {
        let delegate = CertificateAuthenticationDelegate(
            username: username,
            privateKey: .init(custom: privateKey),
            certificate: certificate
        )
        return SSHAuthenticationMethod(custom: delegate)
    }
    
    /// Creates a certificate-based authentication method for P256.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The certificate public key to use for authentication.
    public static func p256Certificate(username: String, privateKey: P256.Signing.PrivateKey, certificate: P256.Signing.CertificatePublicKey) -> SSHAuthenticationMethod {
        let delegate = CertificateAuthenticationDelegate(
            username: username,
            privateKey: .init(p256Key: privateKey),
            certificate: certificate
        )
        return SSHAuthenticationMethod(custom: delegate)
    }
    
    /// Creates a certificate-based authentication method for P384.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The certificate public key to use for authentication.
    public static func p384Certificate(username: String, privateKey: P384.Signing.PrivateKey, certificate: P384.Signing.CertificatePublicKey) -> SSHAuthenticationMethod {
        let delegate = CertificateAuthenticationDelegate(
            username: username,
            privateKey: .init(p384Key: privateKey),
            certificate: certificate
        )
        return SSHAuthenticationMethod(custom: delegate)
    }
    
    /// Creates a certificate-based authentication method for P521.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - privateKey: The private key to authenticate with.
    ///   - certificate: The certificate public key to use for authentication.
    public static func p521Certificate(username: String, privateKey: P521.Signing.PrivateKey, certificate: P521.Signing.CertificatePublicKey) -> SSHAuthenticationMethod {
        let delegate = CertificateAuthenticationDelegate(
            username: username,
            privateKey: .init(p521Key: privateKey),
            certificate: certificate
        )
        return SSHAuthenticationMethod(custom: delegate)
    }
    
    public static func custom(_ auth: NIOSSHClientUserAuthenticationDelegate) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(custom: auth)
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

/// A delegate that handles certificate-based authentication.
internal final class CertificateAuthenticationDelegate: NIOSSHClientUserAuthenticationDelegate {
    private let username: String
    private let privateKey: NIOSSHPrivateKey
    private let certificate: NIOSSHPublicKeyProtocol
    
    init(username: String, privateKey: NIOSSHPrivateKey, certificate: NIOSSHPublicKeyProtocol) {
        self.username = username
        self.privateKey = privateKey
        self.certificate = certificate
    }
    
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard availableMethods.contains(.publicKey) else {
            nextChallengePromise.fail(SSHClientError.unsupportedPrivateKeyAuthentication)
            return
        }
        
        // Convert the Citadel certificate to NIOSSHCertifiedPublicKey
        guard let certifiedKey = CertificateConverter.convertToNIOSSHCertifiedPublicKey(certificate) else {
            // If conversion fails, fall back to regular private key authentication
            let offer = NIOSSHUserAuthenticationOffer(
                username: username,
                serviceName: "",
                offer: .privateKey(.init(privateKey: privateKey))
            )
            nextChallengePromise.succeed(offer)
            return
        }
        
        // Create the authentication offer with the certified key
        let offer = NIOSSHUserAuthenticationOffer(
            username: username,
            serviceName: "",
            offer: .privateKey(.init(privateKey: privateKey, certifiedKey: certifiedKey))
        )
        
        nextChallengePromise.succeed(offer)
    }
}