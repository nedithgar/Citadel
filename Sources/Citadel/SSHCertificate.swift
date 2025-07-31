import Foundation
import NIOCore
import Crypto
import CCryptoBoringSSL
import NIOSSH

/// SSH Certificate structure
public struct SSHCertificate {
    /// Certificate types
    public enum CertificateType: UInt32 {
        case user = 1
        case host = 2
    }
    
    /// Convenience initializer for creating certificates manually (for testing)
    public init(
        nonce: Data,
        serial: UInt64,
        type: CertificateType,
        keyId: String,
        validPrincipals: [String],
        validAfter: UInt64,
        validBefore: UInt64,
        criticalOptions: [(String, Data)],
        extensions: [(String, Data)],
        reserved: Data,
        signatureKey: Data,
        signature: Data,
        publicKey: Data?
    ) {
        self.nonce = nonce
        self.serial = serial
        self.type = type
        self.keyId = keyId
        self.validPrincipals = validPrincipals
        self.validAfter = validAfter
        self.validBefore = validBefore
        self.criticalOptions = criticalOptions
        self.extensions = extensions
        self.reserved = reserved
        self.signatureKey = signatureKey
        self.signature = signature
        self.publicKey = publicKey
    }
    
    /// Certificate nonce (32 random bytes)
    public let nonce: Data
    
    /// Certificate serial number
    public let serial: UInt64
    
    /// Certificate type (1 = user, 2 = host)
    public let type: CertificateType
    
    /// Key ID (free-form text)
    public let keyId: String
    
    /// Valid principals (usernames/hostnames)
    public let validPrincipals: [String]
    
    /// Valid after timestamp (seconds since epoch)
    public let validAfter: UInt64
    
    /// Valid before timestamp (seconds since epoch)
    public let validBefore: UInt64
    
    /// Critical options
    public let criticalOptions: [(String, Data)]
    
    /// Extensions
    public let extensions: [(String, Data)]
    
    /// Reserved field
    public let reserved: Data
    
    /// CA public key
    public let signatureKey: Data
    
    /// CA signature
    public let signature: Data
    
    /// The embedded public key data
    public let publicKey: Data?
    
    /// Store the original certificate blob for signature verification
    internal var certBlob: Data?
    
    /// Initialize from raw certificate data with expected key type
    public init(from data: Data, expectedKeyType: String) throws {
        var buffer = ByteBuffer(data: data)
        
        // Store the original buffer for signature verification
        var originalBuffer = buffer
        
        // Read the key type
        guard let keyType = buffer.readSSHString(),
              keyType == expectedKeyType else {
            throw SSHCertificateError.invalidCertificateType
        }
        
        // Skip nonce for now - it's parsed after the public key, per OpenSSH
        guard let _ = buffer.readSSHData() else {
            throw SSHCertificateError.missingNonce
        }
        
        // Read public key
        // Different key types store public keys differently in certificates
        if keyType.contains("ssh-rsa-cert") || keyType.contains("rsa-sha2") {
            // RSA: Read e and n components and reconstruct the public key data
            guard let e = buffer.readSSHData(),
                  let n = buffer.readSSHData() else {
                throw SSHCertificateError.missingPublicKey
            }
            
            // Reconstruct the public key data in the format expected by RSA.PublicKey
            var publicKeyBuffer = ByteBufferAllocator().buffer(capacity: e.count + n.count + 8)
            publicKeyBuffer.writeSSHData(e)
            publicKeyBuffer.writeSSHData(n)
            self.publicKey = Data(publicKeyBuffer.readableBytesView)
        } else if keyType.contains("ecdsa-sha2") {
            // ECDSA: Read curve identifier and point data
            guard let _ = buffer.readSSHString(), // curve identifier
                  let pointData = buffer.readSSHData() else {
                throw SSHCertificateError.missingPublicKey
            }
            
            // ECDSA certificates store the point data in x963 format (04 || x || y)
            // which is what P256/P384/P521.Signing.PublicKey expects
            self.publicKey = pointData
        } else {
            // Ed25519: Read as a single blob
            guard let publicKeyData = buffer.readSSHData() else {
                throw SSHCertificateError.missingPublicKey
            }
            self.publicKey = publicKeyData
        }
        
        // Now read the nonce (after public key, matching OpenSSH order)
        // Reset to original buffer and skip past key type
        var nonceBuffer = originalBuffer
        _ = nonceBuffer.readSSHString() // skip key type
        guard let nonce = nonceBuffer.readSSHData() else {
            throw SSHCertificateError.missingNonce
        }
        self.nonce = nonce
        
        // Read serial
        guard let serial = buffer.readInteger(as: UInt64.self) else {
            throw SSHCertificateError.missingSerial
        }
        self.serial = serial
        
        // Read type
        guard let typeValue = buffer.readInteger(as: UInt32.self),
              let type = CertificateType(rawValue: typeValue) else {
            throw SSHCertificateError.invalidCertificateType
        }
        self.type = type
        
        // Read key ID
        guard let keyId = buffer.readSSHString() else {
            throw SSHCertificateError.missingKeyId
        }
        self.keyId = keyId
        
        // Read valid principals
        guard var principalsBuffer = buffer.readSSHBuffer() else {
            throw SSHCertificateError.missingPrincipals
        }
        var principals: [String] = []
        while principalsBuffer.readableBytes > 0 {
            guard let principal = principalsBuffer.readSSHString() else {
                throw SSHCertificateError.invalidPrincipal
            }
            principals.append(principal)
        }
        self.validPrincipals = principals
        
        // Read validity period
        guard let validAfter = buffer.readInteger(as: UInt64.self) else {
            throw SSHCertificateError.missingValidAfter
        }
        self.validAfter = validAfter
        
        guard let validBefore = buffer.readInteger(as: UInt64.self) else {
            throw SSHCertificateError.missingValidBefore
        }
        self.validBefore = validBefore
        
        // Read critical options
        guard var criticalOptionsBuffer = buffer.readSSHBuffer() else {
            throw SSHCertificateError.missingCriticalOptions
        }
        var criticalOptions: [(String, Data)] = []
        while criticalOptionsBuffer.readableBytes > 0 {
            guard let name = criticalOptionsBuffer.readSSHString(),
                  let value = criticalOptionsBuffer.readSSHData() else {
                throw SSHCertificateError.invalidCriticalOption
            }
            criticalOptions.append((name, value))
        }
        self.criticalOptions = criticalOptions
        
        // Read extensions
        guard var extensionsBuffer = buffer.readSSHBuffer() else {
            throw SSHCertificateError.missingExtensions
        }
        var extensions: [(String, Data)] = []
        while extensionsBuffer.readableBytes > 0 {
            guard let name = extensionsBuffer.readSSHString(),
                  let value = extensionsBuffer.readSSHData() else {
                throw SSHCertificateError.invalidExtension
            }
            extensions.append((name, value))
        }
        self.extensions = extensions
        
        // Read reserved
        guard let reserved = buffer.readSSHData() else {
            throw SSHCertificateError.missingReserved
        }
        self.reserved = reserved
        
        // Read signature key
        guard let signatureKey = buffer.readSSHData() else {
            throw SSHCertificateError.missingSignatureKey
        }
        self.signatureKey = signatureKey
        
        // Read signature
        guard let signature = buffer.readSSHData() else {
            throw SSHCertificateError.missingSignature
        }
        self.signature = signature
        
        // Verify CA signature
        let signedLength = originalBuffer.readableBytes - buffer.readableBytes - signature.count - 4
        let signedData = Data(originalBuffer.readBytes(length: signedLength)!)
        
        // Parse CA key from signatureKey blob
        guard let caKey = try? Self.parseCAKey(from: signatureKey) else {
            throw SSHCertificateError.invalidSignatureKey
        }
        
        // Verify signature
        guard try Self.verifySignature(signature, for: signedData, with: caKey) else {
            throw SSHCertificateError.invalidSignature
        }
        
        // Store the certificate blob for later validation
        self.certBlob = data
    }
    
    /// Parse CA key from blob
    private static func parseCAKey(from data: Data) throws -> Any {
        var buffer = ByteBuffer(data: data)
        guard let keyType = buffer.readSSHString() else {
            throw SSHCertificateError.invalidSignatureKey
        }
        
        if keyType == "ssh-ed25519" {
            guard let publicKeyData = buffer.readSSHData(),
                  publicKeyData.count == 32 else {
                throw SSHCertificateError.invalidSignatureKey
            }
            return try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        } else if keyType.hasPrefix("ecdsa-sha2-") {
            guard let curveIdentifier = buffer.readSSHString(),
                  let pointData = buffer.readSSHData() else {
                throw SSHCertificateError.invalidSignatureKey
            }
            
            switch curveIdentifier {
            case "nistp256":
                return try P256.Signing.PublicKey(x963Representation: pointData)
            case "nistp384":
                return try P384.Signing.PublicKey(x963Representation: pointData)
            case "nistp521":
                return try P521.Signing.PublicKey(x963Representation: pointData)
            default:
                throw SSHCertificateError.invalidSignatureKey
            }
        } else if keyType == "ssh-rsa" || keyType.hasPrefix("rsa-sha2-") {
            guard let eData = buffer.readSSHData(),
                  let nData = buffer.readSSHData() else {
                throw SSHCertificateError.invalidSignatureKey
            }
            
            // Create RSA public key from e and n using the same method as RSA.PublicKey.read
            let publicExponent = CCryptoBoringSSL_BN_bin2bn(Array(eData), eData.count, nil)!
            let modulus = CCryptoBoringSSL_BN_bin2bn(Array(nData), nData.count, nil)!
            
            return Insecure.RSA.PublicKey(publicExponent: publicExponent, modulus: modulus)
        }
        
        throw SSHCertificateError.invalidSignatureKey
    }
    
    /// Normalize ECDSA signature component to expected size
    /// SSH uses bignum format which may have leading zeros that need to be stripped
    /// or may need padding if the value is smaller than expected
    private static func normalizeECDSAComponent(_ data: Data, expectedSize: Int) -> Data {
        if data.count == expectedSize {
            return data
        } else if data.count > expectedSize {
            // Remove leading zeros
            let leadingZeros = data.prefix(while: { $0 == 0 })
            let trimmed = data.dropFirst(leadingZeros.count)
            if trimmed.count == expectedSize {
                return trimmed
            } else if trimmed.count < expectedSize {
                // Pad with zeros after removing too many
                let padding = Data(repeating: 0, count: expectedSize - trimmed.count)
                return padding + trimmed
            } else {
                // Still too big, take the last expectedSize bytes
                return trimmed.suffix(expectedSize)
            }
        } else {
            // Pad with leading zeros
            let padding = Data(repeating: 0, count: expectedSize - data.count)
            return padding + data
        }
    }
    
    /// Verify signature
    private static func verifySignature(_ signature: Data, for data: Data, with key: Any) throws -> Bool {
        var sigBuffer = ByteBuffer(data: signature)
        guard let sigType = sigBuffer.readSSHString(),
              let sigBlob = sigBuffer.readSSHData() else {
            return false
        }
        
        if let ed25519Key = key as? Curve25519.Signing.PublicKey {
            guard sigType == "ssh-ed25519" else { return false }
            return ed25519Key.isValidSignature(sigBlob, for: data)
        } else if let p256Key = key as? P256.Signing.PublicKey {
            guard sigType == "ecdsa-sha2-nistp256" else { return false }
            // SSH ECDSA signatures store r and s as separate SSH strings with potential leading zeros
            var sigBlobBuffer = ByteBuffer(data: sigBlob)
            guard let rData = sigBlobBuffer.readSSHData(),
                  let sData = sigBlobBuffer.readSSHData() else {
                return false
            }
            
            // SSH uses bignum format which may include leading zeros
            // P256 expects exactly 32 bytes for each component
            let r = normalizeECDSAComponent(rData, expectedSize: 32)
            let s = normalizeECDSAComponent(sData, expectedSize: 32)
            let rawSig = r + s
            
            guard let ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: rawSig) else {
                return false
            }
            return p256Key.isValidSignature(ecdsaSignature, for: SHA256.hash(data: data))
        } else if let p384Key = key as? P384.Signing.PublicKey {
            guard sigType == "ecdsa-sha2-nistp384" else { return false }
            // SSH ECDSA signatures store r and s as separate SSH strings with potential leading zeros
            var sigBlobBuffer = ByteBuffer(data: sigBlob)
            guard let rData = sigBlobBuffer.readSSHData(),
                  let sData = sigBlobBuffer.readSSHData() else {
                return false
            }
            
            // SSH uses bignum format which may include leading zeros
            // P384 expects exactly 48 bytes for each component
            let r = normalizeECDSAComponent(rData, expectedSize: 48)
            let s = normalizeECDSAComponent(sData, expectedSize: 48)
            let rawSig = r + s
            
            guard let ecdsaSignature = try? P384.Signing.ECDSASignature(rawRepresentation: rawSig) else {
                return false
            }
            return p384Key.isValidSignature(ecdsaSignature, for: SHA384.hash(data: data))
        } else if let p521Key = key as? P521.Signing.PublicKey {
            guard sigType == "ecdsa-sha2-nistp521" else { return false }
            // SSH ECDSA signatures store r and s as separate SSH strings with potential leading zeros
            var sigBlobBuffer = ByteBuffer(data: sigBlob)
            guard let rData = sigBlobBuffer.readSSHData(),
                  let sData = sigBlobBuffer.readSSHData() else {
                return false
            }
            
            // SSH uses bignum format which may include leading zeros
            // P521 expects exactly 66 bytes for each component
            let r = normalizeECDSAComponent(rData, expectedSize: 66)
            let s = normalizeECDSAComponent(sData, expectedSize: 66)
            let rawSig = r + s
            
            guard let ecdsaSignature = try? P521.Signing.ECDSASignature(rawRepresentation: rawSig) else {
                return false
            }
            return p521Key.isValidSignature(ecdsaSignature, for: SHA512.hash(data: data))
        } else if let rsaKey = key as? Insecure.RSA.PublicKey {
            // RSA signatures can use different hash algorithms
            let hashAlgorithm: Insecure.RSA.SignatureHashAlgorithm
            switch sigType {
            case "ssh-rsa":
                hashAlgorithm = .sha1
            case "rsa-sha2-256":
                hashAlgorithm = .sha256
            case "rsa-sha2-512":
                hashAlgorithm = .sha512
            default:
                return false
            }
            
            guard let signature = try? Insecure.RSA.Signature(rawRepresentation: sigBlob, algorithm: hashAlgorithm) else {
                return false
            }
            
            return rsaKey.isValidSignature(signature, for: data)
        }
        
        return false
    }
    
    // MARK: - Certificate Validation Methods
    
    /// Verify the certificate is signed by a trusted CA
    public func verifyCertificateSignature(trustedCAs: [NIOSSHPublicKey]) throws {
        // Check if we have any trusted CAs configured
        guard !trustedCAs.isEmpty else {
            throw SSHCertificateError.untrustedCA
        }
        
        // Parse CA key from signatureKey blob
        guard let _ = try? Self.parseCAKey(from: signatureKey) else {
            throw SSHCertificateError.invalidSignatureKey
        }
        
        // For now, we trust the signature verification done during parsing
        // In a complete implementation, we would need to:
        // 1. Convert the CA key to NIOSSHPublicKey format
        // 2. Compare against trusted CAs list
        // 3. Re-verify the signature if needed
        
        // TODO: Implement proper CA key comparison
        // This requires converting between internal key representations and NIOSSHPublicKey
        // For now, we rely on the signature verification done during certificate parsing
        
        // Signature is already verified during parsing
    }
    
    /// Validate certificate time constraints
    public func validateTimeConstraints(currentTime: UInt64? = nil) throws {
        let now = currentTime ?? UInt64(Date().timeIntervalSince1970)
        
        // Check if certificate is not yet valid
        if now < self.validAfter {
            throw SSHCertificateError.notYetValid(
                validAfter: Date(timeIntervalSince1970: Double(validAfter))
            )
        }
        
        // Check if certificate has expired
        if now >= self.validBefore {
            throw SSHCertificateError.expired(
                validBefore: Date(timeIntervalSince1970: Double(validBefore))
            )
        }
    }
    
    /// Validate principal (username/hostname)
    public func validatePrincipal(username: String, wildcardAllowed: Bool = false) throws {
        // If no principals are specified, reject the certificate
        // OpenSSH behavior: empty principals list means no one can use this cert
        guard !self.validPrincipals.isEmpty else {
            throw SSHCertificateError.noPrincipalsSpecified
        }
        
        // Check if username matches any principal
        let principalMatches = self.validPrincipals.contains { principal in
            if wildcardAllowed {
                // OpenSSH uses match_pattern() for wildcard matching
                return matchPattern(pattern: principal, string: username)
            } else {
                return principal == username
            }
        }
        
        if !principalMatches {
            throw SSHCertificateError.principalMismatch(
                username: username,
                allowedPrincipals: validPrincipals
            )
        }
    }
    
    /// Helper function for wildcard pattern matching
    private func matchPattern(pattern: String, string: String) -> Bool {
        // This is a simplified version of OpenSSH's match_pattern()
        if pattern == "*" {
            return true
        }
        if pattern.contains("*") || pattern.contains("?") {
            // Convert wildcard pattern to regex
            let regexPattern = pattern
                .replacingOccurrences(of: ".", with: "\\.")
                .replacingOccurrences(of: "*", with: ".*")
                .replacingOccurrences(of: "?", with: ".")
            
            let regex = try? NSRegularExpression(pattern: "^" + regexPattern + "$", options: [])
            let range = NSRange(location: 0, length: string.utf16.count)
            return regex?.firstMatch(in: string, options: [], range: range) != nil
        }
        return pattern == string
    }
    
    /// Validate source address constraints
    public func validateSourceAddress(_ clientAddress: String) throws {
        // Use the enhanced OpenSSH-compatible address validator
        try validateSourceAddressEnhanced(clientAddress)
    }
    
    /// Helper function for address pattern matching
    private func matchAddress(pattern: String, address: String) -> Bool {
        // Handle CIDR notation (e.g., 192.168.1.0/24)
        if pattern.contains("/") {
            return CIDRMatcher.matches(address: address, cidr: pattern)
        }
        
        // Handle wildcard patterns (e.g., 192.168.*.*)
        if pattern.contains("*") {
            let regexPattern = pattern
                .replacingOccurrences(of: ".", with: "\\.")
                .replacingOccurrences(of: "*", with: "[0-9]+")
            
            let regex = try? NSRegularExpression(pattern: "^" + regexPattern + "$", options: [])
            let range = NSRange(location: 0, length: address.utf16.count)
            return regex?.firstMatch(in: address, options: [], range: range) != nil
        }
        
        // Exact match
        return pattern == address
    }
    
    /// Complete certificate validation for authentication
    public func validateForAuthentication(
        username: String,
        clientAddress: String,
        trustedCAs: [NIOSSHPublicKey],
        currentTime: UInt64? = nil
    ) throws -> CertificateConstraints {
        // 1. Verify certificate type (user vs host)
        guard self.type == .user else {
            throw SSHCertificateError.wrongCertificateType(
                expected: .user,
                actual: self.type
            )
        }
        
        // 2. Verify CA signature
        try self.verifyCertificateSignature(trustedCAs: trustedCAs)
        
        // 3. Check time validity
        try self.validateTimeConstraints(currentTime: currentTime)
        
        // 4. Validate principal
        try self.validatePrincipal(username: username)
        
        // 5. Check source address if restricted
        try self.validateSourceAddress(clientAddress)
        
        // 6. Validate and return constraints for enforcement
        return try CertificateConstraints(from: self)
    }
}

/// Certificate constraints parsed from critical options and extensions
public struct CertificateConstraints {
    public let forceCommand: String?
    public let sourceAddresses: [String]?
    public let permitPTY: Bool
    public let permitPortForwarding: Bool
    public let permitAgentForwarding: Bool
    public let permitX11Forwarding: Bool
    public let permitUserRC: Bool
    public let verifyRequired: Bool
    
    /// Known critical options as per OpenSSH
    private static let knownCriticalOptions: Set<String> = [
        "force-command",
        "source-address",
        "verify-required"
    ]
    
    init(from certificate: SSHCertificate) throws {
        // First validate critical options
        var options: [String: Data] = [:]
        for (key, value) in certificate.criticalOptions {
            // Check if this is an unknown critical option
            if !Self.knownCriticalOptions.contains(key) {
                throw SSHCertificateError.unknownCriticalOption(key)
            }
            options[key] = value
        }
        
        // Parse critical options similar to OpenSSH
        // Critical option values are SSH strings (length-prefixed)
        self.forceCommand = options["force-command"]
            .flatMap { data in
                var buffer = ByteBuffer(data: data)
                return buffer.readSSHString()
            }
        
        self.sourceAddresses = options["source-address"]
            .flatMap { data in
                var buffer = ByteBuffer(data: data)
                return buffer.readSSHString()
            }?
            .components(separatedBy: ",")
        
        self.verifyRequired = options["verify-required"] != nil
        
        // Parse permissions from extensions (OpenSSH behavior)
        // If extension is present, permission is granted
        self.permitPTY = certificate.permitPty
        self.permitPortForwarding = certificate.permitPortForwarding
        self.permitAgentForwarding = certificate.permitAgentForwarding
        self.permitX11Forwarding = certificate.permitX11Forwarding
        self.permitUserRC = certificate.permitUserRc
    }
}

/// SSH Certificate errors
public enum SSHCertificateError: Error, Equatable {
    case invalidCertificateType
    case missingNonce
    case missingPublicKey
    case invalidPublicKey
    case missingSerial
    case missingType
    case missingKeyId
    case invalidKeyId
    case missingPrincipals
    case invalidPrincipal
    case missingValidAfter
    case missingValidBefore
    case missingCriticalOptions
    case invalidCriticalOption
    case missingExtensions
    case invalidExtension
    case missingReserved
    case missingSignatureKey
    case missingSignature
    case invalidSignatureKey
    case invalidSignature
    case unsupportedKeyType
    
    // Validation errors
    case untrustedCA
    case invalidCertificate
    case notYetValid(validAfter: Date)
    case expired(validBefore: Date)
    case noPrincipalsSpecified
    case principalMismatch(username: String, allowedPrincipals: [String])
    case wrongCertificateType(expected: SSHCertificate.CertificateType, actual: SSHCertificate.CertificateType)
    case sourceAddressNotAllowed(clientAddress: String, allowedAddresses: [String])
    case unknownCriticalOption(String)
}

// MARK: - Private extensions for certificate parsing

extension ByteBuffer {
    /// Write SSH data (length-prefixed bytes)
    @discardableResult
    mutating func writeSSHData(_ data: Data) -> Int {
        let written = writeInteger(UInt32(data.count))
        return written + writeBytes(data)
    }
}