import Foundation
import NIOCore

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
    
    public init(username: String? = nil, hostname: String? = nil, sourceAddress: String? = nil, timestamp: UInt64? = nil) {
        self.username = username
        self.hostname = hostname  
        self.sourceAddress = sourceAddress
        self.timestamp = timestamp ?? UInt64(Date().timeIntervalSince1970)
    }
}

/// Certificate validator
public struct SSHCertificateValidator {
    
    /// Validate a certificate in a given context
    public static func validate(_ certificate: SSHCertificate, context: SSHCertificateValidationContext) throws {
        // Check time validity
        if !certificate.isValid(at: context.timestamp) {
            if context.timestamp < certificate.validAfter {
                throw SSHCertificateValidationError.notYetValid
            } else {
                throw SSHCertificateValidationError.expired
            }
        }
        
        // Check principal for user certificates
        if certificate.type == .user, let username = context.username {
            if !certificate.isValid(for: username) {
                throw SSHCertificateValidationError.invalidPrincipal(username)
            }
        }
        
        // Check principal for host certificates
        if certificate.type == .host, let hostname = context.hostname {
            if !certificate.isValid(for: hostname) {
                throw SSHCertificateValidationError.invalidPrincipal(hostname)
            }
        }
        
        // Check source address restriction if present
        if let allowedAddresses = certificate.sourceAddress,
           let actualAddress = context.sourceAddress {
            // Parse the allowed addresses (comma-separated list with possible CIDR notation)
            let allowed = allowedAddresses.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) }
            var isAllowed = false
            
            for pattern in allowed {
                if pattern == actualAddress {
                    isAllowed = true
                    break
                }
                // Check CIDR notation
                if pattern.contains("/") && CIDRMatcher.matches(address: actualAddress, cidr: pattern) {
                    isAllowed = true
                    break
                }
            }
            
            if !isAllowed {
                throw SSHCertificateValidationError.invalidSourceAddress(actualAddress)
            }
        }
    }
}