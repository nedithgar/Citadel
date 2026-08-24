import NIO
import NIOSSH
import Crypto
import Foundation

/// Errors that can occur during SSH authentication
public enum SSHAuthenticationError: Error {
    case certificateValidationFailed(Error)
}

/// Binds an RSA key to one user-authentication signature algorithm without mutating the key.
internal struct RSAAuthenticationPrivateKey: NIOSSHPrivateKeyProtocol {
    static let keyPrefix = Insecure.RSA.PrivateKey.keyPrefix

    let privateKey: Insecure.RSA.PrivateKey
    let algorithm: Insecure.RSA.SignatureHashAlgorithm

    var userAuthenticationAlgorithmIdentifier: String {
        algorithm.rawValue
    }

    var publicKey: NIOSSHPublicKeyProtocol {
        privateKey.publicKey
    }

    func signature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol {
        let signature: Insecure.RSA.Signature = try privateKey.signature(for: data)
        return signature
    }

    func userAuthenticationSignature<D: DataProtocol>(for data: D) throws -> NIOSSHSignatureProtocol {
        switch algorithm {
        case .sha1:
            let signature: Insecure.RSA.Signature = try privateKey.signature(for: data)
            return signature
        case .sha256:
            let signature = try privateKey.signature(for: data, algorithm: .sha256)
            return Insecure.RSA.Sha256Signature(rawRepresentation: signature.rawRepresentation)
        case .sha512:
            let signature = try privateKey.signature(for: data, algorithm: .sha512)
            return Insecure.RSA.Sha512Signature(rawRepresentation: signature.rawRepresentation)
        }
    }
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
    
    /// Creates a legacy `ssh-rsa` public-key authentication method using RSA with SHA-1.
    ///
    /// Prefer ``rsaSha256(username:privateKey:)`` or ``rsaSha512(username:privateKey:)`` when the
    /// server supports RSA SHA-2 authentication.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    ///
    /// Before connecting, explicitly enable RSA with ``SSHAlgorithms/registerRSA()`` or by passing
    /// ``SSHAlgorithms/all`` to the client. RSA registration is process-wide and also enables the
    /// RSA host-key format in NIOSSH, so constructing an authentication method does not perform it.
    public static func rsa(username: String, privateKey: Insecure.RSA.PrivateKey) -> SSHAuthenticationMethod {
        rsa(username: username, privateKey: privateKey, algorithm: .sha1)
    }

    /// Creates an `rsa-sha2-256` public-key authentication method.
    /// - Parameters:
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    ///
    /// Before connecting, explicitly enable RSA with ``SSHAlgorithms/registerRSA()`` or by passing
    /// ``SSHAlgorithms/all`` to the client. RSA registration is process-wide and also enables the
    /// RSA host-key format in NIOSSH, so constructing an authentication method does not perform it.
    public static func rsaSha256(
        username: String,
        privateKey: Insecure.RSA.PrivateKey
    ) -> SSHAuthenticationMethod {
        rsa(username: username, privateKey: privateKey, algorithm: .sha256)
    }

    /// Creates an `rsa-sha2-512` public-key authentication method.
    /// - Parameters:
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    ///
    /// Before connecting, explicitly enable RSA with ``SSHAlgorithms/registerRSA()`` or by passing
    /// ``SSHAlgorithms/all`` to the client. RSA registration is process-wide and also enables the
    /// RSA host-key format in NIOSSH, so constructing an authentication method does not perform it.
    public static func rsaSha512(
        username: String,
        privateKey: Insecure.RSA.PrivateKey
    ) -> SSHAuthenticationMethod {
        rsa(username: username, privateKey: privateKey, algorithm: .sha512)
    }

    private static func rsa(
        username: String,
        privateKey: Insecure.RSA.PrivateKey,
        algorithm: Insecure.RSA.SignatureHashAlgorithm
    ) -> SSHAuthenticationMethod {
        let authenticationKey = RSAAuthenticationPrivateKey(
            privateKey: privateKey,
            algorithm: algorithm
        )
        return SSHAuthenticationMethod(
            username: username,
            offer: .privateKey(.init(privateKey: .init(custom: authenticationKey)))
        )
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
