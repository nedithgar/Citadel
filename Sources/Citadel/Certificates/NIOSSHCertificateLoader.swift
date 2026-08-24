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
    ///
    /// Call ``SSHAlgorithms/registerRSA()`` before loading a certificate whose subject key or
    /// certificate-authority signature uses RSA. Loading never changes NIOSSH's process-wide
    /// algorithm registry implicitly.
    /// - Parameter path: The path to the OpenSSH format certificate file
    /// - Returns: The parsed certificate as NIOSSHCertifiedPublicKey
    /// - Throws: An error if the file cannot be read or parsed
    public static func loadFromOpenSSHFile(at path: String) throws -> NIOSSHCertifiedPublicKey {
        let content = try String(contentsOfFile: path, encoding: .utf8)
        return try loadFromOpenSSHString(content)
    }
    
    /// Loads a certificate from an OpenSSH format string.
    ///
    /// Call ``SSHAlgorithms/registerRSA()`` before loading a certificate whose subject key or
    /// certificate-authority signature uses RSA. Loading never changes NIOSSH's process-wide
    /// algorithm registry implicitly.
    /// - Parameter openSSHString: The OpenSSH format string (e.g., "ssh-ed25519-cert-v01@openssh.com BASE64DATA comment")
    /// - Returns: The parsed certificate as NIOSSHCertifiedPublicKey
    /// - Throws: An error if the string cannot be parsed
    public static func loadFromOpenSSHString(_ openSSHString: String) throws -> NIOSSHCertifiedPublicKey {
        let trimmed = openSSHString.trimmingCharacters(in: .whitespacesAndNewlines)
        let keyType = trimmed.split(
            separator: " ",
            maxSplits: 1,
            omittingEmptySubsequences: true
        ).first.map(String.init)
        if keyType == rsaPublicKeyBlobIdentifier {
            throw NIOSSHCertificateLoadingError.notACertificate
        }

        let needsRSARegistration = requiresRSARegistration(for: trimmed)

        do {
            return try parseCertificate(from: trimmed)
        } catch let error as NIOSSHError {
            guard needsRSARegistration,
                  error.type == .unknownPublicKey || error.type == .unknownSignature else {
                throw error
            }

            // Registering a custom key parser also advertises it as a host-key algorithm to every
            // subsequent NIOSSH client in this process. Keep that irreversible choice explicit.
            throw NIOSSHCertificateLoadingError.unsupportedCertificateType
        }
    }
    
    /// Loads a certificate from binary data.
    ///
    /// Call ``SSHAlgorithms/registerRSA()`` first when the certificate uses RSA. This method does
    /// not change NIOSSH's process-wide algorithm registry implicitly.
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
    ///
    /// Call ``SSHAlgorithms/registerRSA()`` first when any certificate uses RSA. Unsupported or
    /// malformed lines are omitted, consistent with this method's existing best-effort behavior.
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

    private static func parseCertificate(from openSSHString: String) throws -> NIOSSHCertifiedPublicKey {
        let publicKey = try NIOSSHPublicKey(openSSHPublicKey: openSSHString)

        guard let certifiedKey = NIOSSHCertifiedPublicKey(publicKey) else {
            throw NIOSSHCertificateLoadingError.notACertificate
        }

        return certifiedKey
    }

    /// Determines whether parsing this OpenSSH value needs the caller to register Citadel's custom RSA types.
    ///
    /// RSA may appear either as the certificate's subject key or as the CA signature
    /// algorithm in the certificate's final SSH field.
    static func requiresRSARegistration(for openSSHString: String) -> Bool {
        let components = openSSHString.split(
            separator: " ",
            maxSplits: 2,
            omittingEmptySubsequences: true
        )
        guard components.count >= 2,
              let certificateData = Data(base64Encoded: String(components[1])) else {
            return false
        }

        var certificateBuffer = ByteBufferAllocator().buffer(capacity: certificateData.count)
        certificateBuffer.writeBytes(certificateData)
        guard let embeddedKeyType = certificateBuffer.readSSHString(),
              embeddedKeyType == components[0] else {
            return false
        }

        guard certificateBuffer.readSSHData() != nil else { // nonce
            return false
        }

        let subjectUsesRSA: Bool
        switch embeddedKeyType {
        case "ssh-rsa-cert-v01@openssh.com":
            guard certificateBuffer.readSSHData() != nil, // public exponent
                  certificateBuffer.readSSHData() != nil else { // modulus
                return false
            }
            subjectUsesRSA = true
        case "ssh-ed25519-cert-v01@openssh.com":
            guard certificateBuffer.readSSHData() != nil else { // public key
                return false
            }
            subjectUsesRSA = false
        case "ecdsa-sha2-nistp256-cert-v01@openssh.com",
             "ecdsa-sha2-nistp384-cert-v01@openssh.com",
             "ecdsa-sha2-nistp521-cert-v01@openssh.com":
            guard certificateBuffer.readSSHData() != nil, // curve name
                  certificateBuffer.readSSHData() != nil else { // public key
                return false
            }
            subjectUsesRSA = false
        default:
            return false
        }

        guard certificateBuffer.readInteger(as: UInt64.self) != nil, // serial
              certificateBuffer.readInteger(as: UInt32.self) != nil, // certificate type
              certificateBuffer.readSSHData() != nil, // key ID
              certificateBuffer.readSSHData() != nil, // principals
              certificateBuffer.readInteger(as: UInt64.self) != nil, // valid after
              certificateBuffer.readInteger(as: UInt64.self) != nil, // valid before
              certificateBuffer.readSSHData() != nil, // critical options
              certificateBuffer.readSSHData() != nil, // extensions
              certificateBuffer.readSSHData() != nil, // reserved
              certificateBuffer.readSSHData() != nil, // signature key
              let signature = certificateBuffer.readSSHData(),
              certificateBuffer.readableBytes == 0 else {
            return false
        }

        var signatureBuffer = ByteBufferAllocator().buffer(capacity: signature.count)
        signatureBuffer.writeBytes(signature)
        guard let signatureAlgorithm = signatureBuffer.readSSHString(),
              signatureBuffer.readSSHData() != nil,
              signatureBuffer.readableBytes == 0 else {
            return false
        }

        return subjectUsesRSA || rsaSignatureAlgorithms.contains(signatureAlgorithm)
    }

    private static let rsaSignatureAlgorithms: Set<String> = [
        "ssh-rsa",
        "rsa-sha2-256",
        "rsa-sha2-512",
    ]

    private static let rsaCertificateBlobIdentifier = "ssh-rsa-cert-v01@openssh.com"
    private static let rsaPublicKeyBlobIdentifier = "ssh-rsa"

}
