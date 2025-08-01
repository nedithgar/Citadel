import Foundation
import NIOCore
import NIOSSH

/// SSH Certificate validation utilities
public extension SSHCertificate {
    
    /// Check if the certificate is currently valid based on time
    var isValidNow: Bool {
        let now = UInt64(Date().timeIntervalSince1970)
        return now >= validAfter && now <= validBefore
    }
    
    /// Check if the certificate is valid at a specific time
    func isValid(at timestamp: UInt64) -> Bool {
        return timestamp >= validAfter && timestamp <= validBefore
    }
    
    /// Check if the certificate is valid for a specific principal
    func isValid(for principal: String) -> Bool {
        // Empty principals list means valid for all principals
        if validPrincipals.isEmpty {
            return true
        }
        return validPrincipals.contains(principal)
    }
    
    /// Get the force-command critical option if present
    var forceCommand: String? {
        for (name, data) in criticalOptions {
            if name == "force-command" {
                // The value is SSH string encoded
                var buffer = ByteBuffer(data: data)
                return buffer.readSSHString()
            }
        }
        return nil
    }
    
    /// Get the source-address critical option if present
    var sourceAddress: String? {
        for (name, data) in criticalOptions {
            if name == "source-address" {
                // The value is SSH string encoded
                var buffer = ByteBuffer(data: data)
                return buffer.readSSHString()
            }
        }
        return nil
    }
    
    /// Check if permit-X11-forwarding extension is present
    var permitX11Forwarding: Bool {
        return extensions.contains { $0.0 == "permit-X11-forwarding" }
    }
    
    /// Check if permit-agent-forwarding extension is present
    var permitAgentForwarding: Bool {
        return extensions.contains { $0.0 == "permit-agent-forwarding" }
    }
    
    /// Check if permit-port-forwarding extension is present
    var permitPortForwarding: Bool {
        return extensions.contains { $0.0 == "permit-port-forwarding" }
    }
    
    /// Check if permit-pty extension is present
    var permitPty: Bool {
        return extensions.contains { $0.0 == "permit-pty" }
    }
    
    /// Check if permit-user-rc extension is present
    var permitUserRc: Bool {
        return extensions.contains { $0.0 == "permit-user-rc" }
    }
    
    /// Check if no-touch-required extension is present
    var noTouchRequired: Bool {
        return extensions.contains { $0.0 == "no-touch-required" }
    }
}

/// Extended validation errors
public enum SSHCertificateValidationError: Error {
    case expired
    case notYetValid
    case invalidPrincipal(String)
    case invalidSourceAddress(String)
    case invalidCertificateType(expected: SSHCertificate.CertificateType, got: SSHCertificate.CertificateType)
}

/// Certificate validation context
public struct SSHCertificateValidationContext {
    public let username: String?
    public let hostname: String?
    public let sourceAddress: String?
    public let timestamp: UInt64
    public let trustedCAs: [NIOSSHPublicKey]
    
    public init(username: String? = nil, hostname: String? = nil, sourceAddress: String? = nil, timestamp: UInt64? = nil, trustedCAs: [NIOSSHPublicKey] = []) {
        self.username = username
        self.hostname = hostname  
        self.sourceAddress = sourceAddress
        self.timestamp = timestamp ?? UInt64(Date().timeIntervalSince1970)
        self.trustedCAs = trustedCAs
    }
}

/// Certificate validator
public struct SSHCertificateValidator {
    
    /// Validate a certificate in a given context (legacy method for compatibility)
    public static func validate(_ certificate: SSHCertificate, context: SSHCertificateValidationContext) throws {
        // For user certificates
        if certificate.type == .user, let username = context.username {
            // Use the new comprehensive validation
            let clientAddress = context.sourceAddress ?? "0.0.0.0"
            _ = try certificate.validateForAuthentication(
                username: username,
                clientAddress: clientAddress,
                trustedCAs: context.trustedCAs,
                currentTime: context.timestamp
            )
        }
        // For host certificates
        else if certificate.type == .host {
            // Verify certificate type
            guard certificate.type == .host else {
                throw SSHCertificateValidationError.invalidCertificateType(
                    expected: .host,
                    got: certificate.type
                )
            }
            
            // Verify CA signature
            try certificate.verifyCertificateSignature(trustedCAs: context.trustedCAs)
            
            // Check time validity
            try certificate.validateTimeConstraints(currentTime: context.timestamp)
            
            // Validate hostname if provided
            if let hostname = context.hostname {
                try certificate.validatePrincipal(username: hostname, wildcardAllowed: true, requirePrincipal: false)
            }
            
            // Check source address if provided
            if let sourceAddress = context.sourceAddress {
                try certificate.validateSourceAddress(sourceAddress)
            }
        }
    }
    
    /// Validate a user certificate with full security checks
    public static func validateUserCertificate(
        _ certificate: SSHCertificate,
        username: String,
        clientAddress: String,
        trustedCAs: [NIOSSHPublicKey]
    ) throws -> CertificateConstraints {
        return try certificate.validateForAuthentication(
            username: username,
            clientAddress: clientAddress,
            trustedCAs: trustedCAs
        )
    }
    
    /// Validate a host certificate
    public static func validateHostCertificate(
        _ certificate: SSHCertificate,
        hostname: String,
        trustedCAs: [NIOSSHPublicKey]
    ) throws {
        // Verify certificate type
        guard certificate.type == .host else {
            throw SSHCertificateError.wrongCertificateType(
                expected: .host,
                actual: certificate.type
            )
        }
        
        // Verify CA signature
        try certificate.verifyCertificateSignature(trustedCAs: trustedCAs)
        
        // Check time validity
        try certificate.validateTimeConstraints()
        
        // Validate hostname with wildcard support
        try certificate.validatePrincipal(username: hostname, wildcardAllowed: true)
    }
}