import Foundation
import NIO
import NIOCore
import Crypto
import _CryptoExtras
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
        signatureType: String? = nil,
        publicKey: Data?,
        keyType: String? = nil
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
        self.signatureType = signatureType
        self.publicKey = publicKey
        self._keyType = keyType
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
    
    /// Signature algorithm type (e.g., "ssh-rsa", "rsa-sha2-256", "ssh-ed25519")
    public let signatureType: String?
    
    /// The embedded public key data
    public let publicKey: Data?
    
    /// Store the original certificate blob for signature verification
    internal var certBlob: Data?
    
    /// Stores the key type for RSA validation (used when created via convenience init)
    private var _keyType: String?
    
    /// Initialize from raw certificate data with expected key type
    public init(from data: Data, expectedKeyType: String) throws {
        var buffer = ByteBuffer(data: data)
        
        // Store the original data for signature verification
        let originalData = data
        
        // Read the key type
        guard let keyType = buffer.readSSHString(),
              keyType == expectedKeyType else {
            throw SSHCertificateError.invalidCertificateType
        }
        
        // Read nonce as the first field after key type (per OpenSSH format)
        guard let nonce = buffer.readSSHData() else {
            throw SSHCertificateError.missingNonce
        }
        self.nonce = nonce
        
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
        
        // Extract signature type from the signature blob
        self.signatureType = Self.extractSignatureType(from: signature)
        
        // Verify CA signature
        // The signed data is everything before the signature field
        // Calculate length: total data length - remaining buffer - signature length - 4 bytes for signature length prefix
        let signedLength = originalData.count - buffer.readableBytes - signature.count - 4
        let signedData = originalData.prefix(signedLength)
        
        // Parse CA key from signatureKey blob
        guard let caKey = try? Self.parseCAKey(from: signatureKey) else {
            throw SSHCertificateError.invalidSignatureKey
        }
        
        // Verify signature
        guard try Self.verifySignature(signature, for: Data(signedData), with: caKey) else {
            throw SSHCertificateError.invalidSignature
        }
        
        // Store the certificate blob for later validation
        self.certBlob = originalData
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
    
    /// Extract signature type from signature blob
    private static func extractSignatureType(from signature: Data) -> String? {
        var sigBuffer = ByteBuffer(data: signature)
        return sigBuffer.readSSHString()
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
    
    /// Check if the certificate's signature type is allowed
    /// - Parameter allowedAlgorithms: Comma-separated list of allowed signature algorithms (e.g., "ssh-rsa,rsa-sha2-256,rsa-sha2-512")
    /// - Returns: true if the signature type is allowed, false otherwise
    public func checkSignatureType(allowedAlgorithms: String?) -> Bool {
        // If no allowed algorithms are specified, accept any
        guard let allowed = allowedAlgorithms, !allowed.isEmpty else {
            return true
        }
        
        // If we don't have a signature type, reject
        guard let sigType = self.signatureType else {
            return false
        }
        
        // Check if the signature type matches any allowed algorithm
        let allowedList = allowed.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        return allowedList.contains(sigType)
    }
    
    /// Verify the certificate is signed by a trusted CA
    public func verifyCertificateSignature(trustedCAs: [NIOSSHPublicKey]) throws {
        // Check if we have any trusted CAs configured
        guard !trustedCAs.isEmpty else {
            throw SSHCertificateError.untrustedCA
        }
        
        // Verify that we can parse CA key from signatureKey blob
        // (The actual signature verification was already done during certificate parsing)
        guard let _ = try? Self.parseCAKey(from: signatureKey) else {
            throw SSHCertificateError.invalidSignatureKey
        }
        
        // Convert the CA key to NIOSSHPublicKey format by serializing and parsing
        // This is necessary because NIOSSHPublicKey's BackingKey enum is internal
        let caPublicKey: NIOSSHPublicKey
        
        // Build the OpenSSH format string from the signatureKey data
        var keyBuffer = ByteBuffer(data: signatureKey)
        guard let keyType = keyBuffer.readSSHString() else {
            throw SSHCertificateError.invalidSignatureKey
        }
        
        // Create the OpenSSH format string
        let base64Key = signatureKey.base64EncodedString()
        let openSSHString = "\(keyType) \(base64Key)"
        
        do {
            caPublicKey = try NIOSSHPublicKey(openSSHPublicKey: openSSHString)
        } catch {
            throw SSHCertificateError.invalidSignatureKey
        }
        
        // Check if the CA key is in the trusted CAs list
        var caKeyFound = false
        for trustedCA in trustedCAs {
            if trustedCA == caPublicKey {
                caKeyFound = true
                break
            }
        }
        
        if !caKeyFound {
            throw SSHCertificateError.untrustedCA
        }
        
        // The signature was already verified during parsing
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
    public func validatePrincipal(username: String, wildcardAllowed: Bool = false, requirePrincipal: Bool = true) throws {
        // OpenSSH behavior: empty principals handling depends on require_principal flag
        if self.validPrincipals.isEmpty {
            if requirePrincipal {
                throw SSHCertificateError.noPrincipalsSpecified
            }
            // If require_principal is false, empty principals are allowed (matches any username)
            return
        }
        
        // If principals are specified, check if username matches any principal
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
        // Use the new OpenSSH-compatible pattern matcher
        return PatternMatcher.match(string, pattern: pattern)
    }
    
    /// Validate source address constraints
    public func validateSourceAddress(_ clientAddress: String) throws {
        // Use the enhanced OpenSSH-compatible address validator
        try validateSourceAddressEnhanced(clientAddress)
    }
    
    /// Helper function for address pattern matching
    private func matchAddress(pattern: String, address: String) -> Bool {
        // Use the new OpenSSH-compatible address matcher
        return PatternMatcher.matchAddress(address, pattern: pattern)
    }
    
    /// Check RSA key length - equivalent to OpenSSH's sshkey_check_rsa_length
    /// - Parameter minimumBits: Minimum allowed RSA key size in bits (default: 1024)
    /// - Throws: SSHCertificateError.rsaKeyTooShort if the key is too short
    public func checkRSAKeyLength(minimumBits: Int = 1024) throws {
        // Only check RSA certificates
        guard let keyTypeString = self.keyType,
              (keyTypeString.contains("ssh-rsa-cert") || keyTypeString.contains("rsa-sha2")) else {
            // Not an RSA certificate, no check needed
            return
        }
        
        // Parse the public key to get the modulus
        guard let publicKey = self.publicKey else {
            throw SSHCertificateError.invalidPublicKey
        }
        
        var buffer = ByteBuffer(data: publicKey)
        
        // Read e and n components
        guard let _ = buffer.readSSHData(),
              let nData = buffer.readSSHData() else {
            throw SSHCertificateError.invalidPublicKey
        }
        
        // Calculate the bit length of the modulus (n)
        // The bit length is approximately log2(n) = (number of bytes * 8) - leading zero bits
        let modulusBits = nData.count * 8 - countLeadingZeroBits(in: nData)
        
        // Check against minimum requirement (OpenSSH default is 1024 bits)
        if modulusBits < minimumBits {
            throw SSHCertificateError.rsaKeyTooShort(bits: modulusBits, minimumBits: minimumBits)
        }
    }
    
    /// Count leading zero bits in a byte array
    private func countLeadingZeroBits(in data: Data) -> Int {
        guard !data.isEmpty else { return 0 }
        
        var leadingZeroBits = 0
        for byte in data {
            if byte == 0 {
                leadingZeroBits += 8
            } else {
                // Count leading zero bits in the first non-zero byte
                var mask: UInt8 = 0x80
                while (byte & mask) == 0 && mask > 0 {
                    leadingZeroBits += 1
                    mask >>= 1
                }
                break
            }
        }
        return leadingZeroBits
    }
    
    /// Key type extracted from the certificate - stored for RSA length validation
    private var keyType: String? {
        // Use stored key type if available (from convenience init)
        if let storedKeyType = _keyType {
            return storedKeyType
        }
        
        // Extract key type from the beginning of the certificate blob
        guard let certBlob = self.certBlob else { return nil }
        var buffer = ByteBuffer(data: certBlob)
        return buffer.readSSHString()
    }
    
    /// Complete certificate validation for authentication
    public func validateForAuthentication(
        username: String,
        clientAddress: String,
        trustedCAs: [NIOSSHPublicKey],
        currentTime: UInt64? = nil,
        requirePrincipal: Bool = true,
        allowedSignatureAlgorithms: String? = nil,
        minimumRSABits: Int = 1024
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
        
        // 3. Check if signature algorithm is allowed
        if !self.checkSignatureType(allowedAlgorithms: allowedSignatureAlgorithms) {
            throw SSHCertificateError.disallowedSignatureAlgorithm(
                algorithm: self.signatureType ?? "unknown"
            )
        }
        
        // 4. Check RSA key length (if applicable)
        try self.checkRSAKeyLength(minimumBits: minimumRSABits)
        
        // 5. Check time validity
        try self.validateTimeConstraints(currentTime: currentTime)
        
        // 6. Validate principal
        try self.validatePrincipal(username: username, requirePrincipal: requirePrincipal)
        
        // 7. Check source address if restricted
        try self.validateSourceAddress(clientAddress)
        
        // 8. Validate and return constraints for enforcement
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
    case disallowedSignatureAlgorithm(algorithm: String)
    case rsaKeyTooShort(bits: Int, minimumBits: Int)
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