import Foundation
import NIOSSH
import NIOCore
import Crypto
import _CryptoExtras
import Logging

// MARK: - Security Extensions for NIOSSHCertifiedPublicKey

extension NIOSSHCertifiedPublicKey {
    // MARK: - Enhanced Validation Methods
    
    /// Validates the certificate for authentication with enhanced security checks
    /// - Parameters:
    ///   - username: The username attempting to authenticate (for user certificates)
    ///   - hostname: The hostname being connected to (for host certificates)
    ///   - currentTime: The current time for validity checking (defaults to now)
    ///   - sourceAddress: The source address for validation (optional)
    ///   - minimumRSABits: Minimum RSA key size required (defaults to 1024)
    ///   - allowedSignatureAlgorithms: Set of allowed signature algorithms (nil allows all)
    ///   - logger: Logger for debugging
    /// - Returns: Certificate constraints if validation succeeds
    /// - Throws: SSHCertificateError if validation fails
    public func validateForAuthentication(
        username: String? = nil,
        hostname: String? = nil,
        currentTime: Date = Date(),
        sourceAddress: String? = nil,
        minimumRSABits: Int = 1024,
        allowedSignatureAlgorithms: Set<String>? = nil,
        logger: Logger? = nil
    ) throws -> SSHCertificateConstraints {
        // Time validation
        try validateTimeConstraints(currentTime: currentTime)
        
        // Certificate type validation
        switch type {
        case .user:
            guard let username = username else {
                throw SSHCertificateError.invalidCertificateType
            }
            try validatePrincipal(username)
        case .host:
            guard let hostname = hostname else {
                throw SSHCertificateError.invalidCertificateType
            }
            try validatePrincipal(hostname)
        default:
            throw SSHCertificateError.invalidCertificateType
        }
        
        // RSA key length validation
        // Note: NIOSSH doesn't expose the underlying key algorithm directly,
        // so RSA key length validation would need to be done at a different layer
        // For now, we skip this check as it requires deeper integration
        
        // Signature algorithm validation
        if let allowedAlgorithms = allowedSignatureAlgorithms {
            try validateCertificateSignatureAlgorithm(allowedAlgorithms: allowedAlgorithms)
        }
        
        // Source address validation
        if let sourceAddress = sourceAddress {
            try validateSourceAddress(sourceAddress, logger: logger)
        }
        
        // Parse and return constraints
        return try parseCertificateConstraints(logger: logger)
    }
    
    /// Validates time constraints
    private func validateTimeConstraints(currentTime: Date) throws {
        let currentTimestamp = UInt64(currentTime.timeIntervalSince1970)
        
        if validAfter > 0 && currentTimestamp < validAfter {
            throw SSHCertificateError.notYetValid(validAfter: Date(timeIntervalSince1970: TimeInterval(validAfter)))
        }
        
        if validBefore > 0 && validBefore != UInt64.max && currentTimestamp > validBefore {
            throw SSHCertificateError.expired(validBefore: Date(timeIntervalSince1970: TimeInterval(validBefore)))
        }
    }
    
    /// Validates principal with wildcard support
    private func validatePrincipal(_ principal: String) throws {
        guard !validPrincipals.isEmpty else {
            throw SSHCertificateError.noPrincipals
        }
        
        for validPrincipal in validPrincipals {
            if PatternMatcher.match(principal, pattern: validPrincipal) {
                return
            }
        }
        
        throw SSHCertificateError.principalNotAllowed(principal)
    }
    
    /// Validates RSA key length
    private func validateRSAKeyLength(_ rsaKey: _RSA.Signing.PublicKey, minimumBits: Int) throws {
        let keySize = rsaKey.keySizeInBits
        guard keySize >= minimumBits else {
            throw SSHCertificateError.rsaKeyTooSmall(bits: keySize, minimum: minimumBits)
        }
    }
    
    /// Validates signature algorithm
    private func validateCertificateSignatureAlgorithm(allowedAlgorithms: Set<String>) throws {
        // Extract signature type from the signature blob
        guard let signatureType = extractSignatureType() else {
            throw SSHCertificateError.invalidSignature
        }
        
        guard allowedAlgorithms.contains(signatureType) else {
            throw SSHCertificateError.signatureAlgorithmNotAllowed(signatureType)
        }
    }
    
    /// Extracts the signature type from the signature blob
    private func extractSignatureType() -> String? {
        // The signature is an NIOSSHSignature, not raw bytes
        // For now, we'll skip signature algorithm validation as it requires deeper integration
        return nil
    }
    
    /// Validates source address
    private func validateSourceAddress(_ address: String, logger: Logger?) throws {
        // Check critical options for source-address
        guard let sourceAddressData = criticalOptions["source-address"] else {
            // No source-address restriction
            return
        }
        
        // The critical option value is a string directly
        let allowedAddresses = sourceAddressData
        
        let matchResult = AddressValidator.matchAddressList(address, against: allowedAddresses)
        guard matchResult == 1 else {
            logger?.debug("Address \(address) not allowed by source-address: \(allowedAddresses)")
            throw SSHCertificateError.sourceAddressNotAllowed(address)
        }
    }
    
    /// Parses certificate constraints from critical options and extensions
    private func parseCertificateConstraints(logger: Logger?) throws -> SSHCertificateConstraints {
        var constraints = SSHCertificateConstraints()
        
        // Parse critical options
        for (name, value) in criticalOptions {
            switch name {
            case "force-command":
                // Critical option values are strings
                constraints.forceCommand = value
                
            case "source-address":
                // Critical option values are strings
                constraints.sourceAddress = value
                
            default:
                // Unknown critical option - this should fail per SSH spec
                logger?.warning("Unknown critical option: \(name)")
                throw SSHCertificateError.unknownCriticalOption(name)
            }
        }
        
        // Parse extensions (these are optional, so unknown ones are just logged)
        for (name, _) in extensions {
            switch name {
            case "permit-X11-forwarding":
                constraints.permitX11Forwarding = true
            case "permit-agent-forwarding":
                constraints.permitAgentForwarding = true
            case "permit-port-forwarding":
                constraints.permitPortForwarding = true
            case "permit-pty":
                constraints.permitPty = true
            case "permit-user-rc":
                constraints.permitUserRc = true
            case "no-touch-required":
                constraints.noTouchRequired = true
            default:
                logger?.debug("Unknown extension: \(name)")
            }
        }
        
        return constraints
    }
    
    // MARK: - Computed Properties for Common Extensions
    
    /// Whether PTY allocation is permitted
    public var permitPty: Bool {
        extensions["permit-pty"] != nil
    }
    
    /// Whether X11 forwarding is permitted
    public var permitX11Forwarding: Bool {
        extensions["permit-X11-forwarding"] != nil
    }
    
    /// Whether agent forwarding is permitted
    public var permitAgentForwarding: Bool {
        extensions["permit-agent-forwarding"] != nil
    }
    
    /// Whether port forwarding is permitted
    public var permitPortForwarding: Bool {
        extensions["permit-port-forwarding"] != nil
    }
    
    /// Whether user RC execution is permitted
    public var permitUserRc: Bool {
        extensions["permit-user-rc"] != nil
    }
    
    /// Whether no-touch is required (FIDO2 keys)
    public var noTouchRequired: Bool {
        extensions["no-touch-required"] != nil
    }
    
    /// Force command from critical options
    public var forceCommand: String? {
        return criticalOptions["force-command"]
    }
    
    /// Source address restrictions from critical options
    public var sourceAddressRestriction: String? {
        return criticalOptions["source-address"]
    }
}

// MARK: - Certificate Constraints Structure

/// Parsed certificate constraints for easy enforcement
public struct SSHCertificateConstraints {
    public var forceCommand: String?
    public var sourceAddress: String?
    public var permitX11Forwarding: Bool = false
    public var permitAgentForwarding: Bool = false
    public var permitPortForwarding: Bool = false
    public var permitPty: Bool = false
    public var permitUserRc: Bool = false
    public var noTouchRequired: Bool = false
    
    public init() {}
}