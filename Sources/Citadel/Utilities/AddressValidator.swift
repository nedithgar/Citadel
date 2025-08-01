import Foundation
import Network
import NIOCore
import NIOSSH

/// Enhanced address validation matching OpenSSH's addr_match_list() behavior
public struct AddressValidator {
    
    /// Match an address against a comma-separated list of patterns
    /// Supports:
    /// - CIDR notation (192.168.1.0/24)
    /// - Exact IP matches (192.168.1.1)
    /// - Negation with ! prefix (!192.168.1.100)
    /// - Wildcard patterns (192.168.*.*)
    /// - IPv6 addresses
    ///
    /// Returns:
    /// - 1: Match found
    /// - 0: No match
    /// - -1: Negated match (address is explicitly denied)
    /// - -2: Invalid list format
    public static func matchAddressList(_ address: String, against list: String) -> Int {
        // Use components(separatedBy:) instead of split to handle trailing commas properly
        let patterns = list.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        
        for pattern in patterns {
            // Skip empty patterns (e.g., from trailing comma)
            if pattern.isEmpty {
                continue
            }
            
            var checkPattern = pattern
            let isNegated = pattern.hasPrefix("!")
            if isNegated {
                checkPattern = String(pattern.dropFirst())
            }
            
            let matches: Bool
            
            // Try CIDR notation first
            if checkPattern.contains("/") {
                matches = matchCIDR(address: address, cidr: checkPattern)
            }
            // Try exact match
            else if checkPattern == address {
                matches = true
            }
            // Try wildcard pattern
            else if checkPattern.contains("*") {
                matches = matchWildcard(address: address, pattern: checkPattern)
            }
            // Try as plain IP address
            else {
                matches = (checkPattern == address)
            }
            
            if matches {
                return isNegated ? -1 : 1
            }
        }
        
        return 0 // No match found
    }
    
    /// Match an address against a strict CIDR-only list
    /// This is equivalent to OpenSSH's addr_match_cidr_list()
    /// - Only CIDR notation is allowed (no wildcards, no negation)
    /// - Used for certificate source-address validation
    /// 
    /// Returns:
    /// - 1: Match found
    /// - 0: No match
    /// - -1: Invalid list format
    public static func matchCIDRList(_ address: String?, against list: String) -> Int {
        // Validate the list structure first
        guard validateCIDRList(list) else {
            return -1
        }
        
        // If address is nil, we're just validating the list structure
        guard let address = address else {
            return 0
        }
        
        let patterns = list.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        
        for pattern in patterns {
            // Skip empty patterns
            if pattern.isEmpty {
                continue
            }
            
            // Handle both CIDR notation and plain IP addresses (OpenSSH behavior)
            let cidrPattern: String
            if pattern.contains("/") {
                cidrPattern = pattern
            } else {
                // Plain IP address - add default mask like OpenSSH
                if pattern.contains(":") {
                    cidrPattern = "\(pattern)/128"  // IPv6 single host
                } else {
                    cidrPattern = "\(pattern)/32"   // IPv4 single host
                }
            }
            
            if matchCIDR(address: address, cidr: cidrPattern) {
                return 1
            }
        }
        
        return 0 // No match found
    }
    
    /// Validate that a source address list has valid syntax
    /// Used for validating certificate critical options
    public static func validateAddressList(_ list: String) -> Bool {
        // Empty list is invalid
        guard !list.trimmingCharacters(in: .whitespaces).isEmpty else {
            return false
        }
        
        let patterns = list.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        
        for pattern in patterns {
            // Skip empty patterns (from trailing commas or double commas)
            if pattern.isEmpty {
                continue
            }
            
            var checkPattern = pattern
            if pattern.hasPrefix("!") {
                checkPattern = String(pattern.dropFirst())
                // Pattern after ! must not be empty
                guard !checkPattern.isEmpty else {
                    return false
                }
            }
            
            // Validate pattern format
            if checkPattern.contains("/") {
                // Validate CIDR notation
                if !isValidCIDR(checkPattern) {
                    return false
                }
            } else if checkPattern.contains("*") {
                // Wildcard patterns are always valid if non-empty
                continue
            } else {
                // Validate as IP address
                if !isValidIPAddress(checkPattern) {
                    return false
                }
            }
        }
        
        return true
    }
    
    /// Match an address against a CIDR list (strict mode - no wildcards)
    /// This is used for certificate validation where only CIDR notation is allowed
    /// Matches OpenSSH's addr_match_cidr_list() behavior
    /// - Parameters:
    ///   - address: The IP address to check
    ///   - cidrList: Comma-separated list of CIDR patterns (no wildcards, no negation)
    /// - Returns: 1 if match, 0 if no match, -1 on error
    public static func matchCIDRList(_ address: String, against cidrList: String) -> Int {
        // Validate CIDR list format first
        guard validateCIDRList(cidrList) else {
            return -1 // Invalid format
        }
        
        let patterns = cidrList.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        
        for pattern in patterns {
            guard !pattern.isEmpty else { continue }
            
            // No negation allowed in strict CIDR mode
            if pattern.hasPrefix("!") {
                return -1
            }
            
            // Handle both CIDR notation and plain IP addresses (OpenSSH behavior)
            let cidrPattern: String
            if pattern.contains("/") {
                cidrPattern = pattern
            } else {
                // Plain IP address - add default mask like OpenSSH
                if pattern.contains(":") {
                    cidrPattern = "\(pattern)/128"  // IPv6 single host
                } else {
                    cidrPattern = "\(pattern)/32"   // IPv4 single host
                }
            }
            
            if matchCIDR(address: address, cidr: cidrPattern) {
                return 1
            }
        }
        
        return 0
    }
    
    /// Validate a CIDR list has valid format (strict mode)
    /// Matches OpenSSH's validation in addr_match_cidr_list()
    public static func validateCIDRList(_ cidrList: String) -> Bool {
        // Check for valid characters only
        let validChars = CharacterSet(charactersIn: "0123456789abcdefABCDEF.:/,")
        let invalidChars = CharacterSet(charactersIn: cidrList).subtracting(validChars)
        guard invalidChars.isEmpty else {
            return false
        }
        
        let patterns = cidrList.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        
        for pattern in patterns {
            // OpenSSH returns error for empty entries
            if pattern.isEmpty {
                return false
            }
            
            // No negation allowed in strict mode
            if pattern.hasPrefix("!") {
                return false
            }
            
            // Must be valid CIDR or plain IP address (OpenSSH behavior)
            if pattern.contains("/") {
                if !isValidCIDR(pattern) {
                    return false
                }
            } else {
                // Plain IP address is allowed - will be treated as /32 or /128
                if !isValidIPAddress(pattern) {
                    return false
                }
            }
            
            // Check length limits (INET6_ADDRSTRLEN + 3)
            if pattern.count > 46 + 3 { // IPv6 max length + "/128"
                return false
            }
        }
        
        return true
    }
    
    // MARK: - Private Helpers
    
    private static func matchCIDR(address: String, cidr: String) -> Bool {
        // For IPv6, use Network framework
        if address.contains(":") || cidr.contains(":") {
            return matchIPv6CIDR(address: address, cidr: cidr)
        }
        
        // For IPv4, use our existing CIDRMatcher
        return CIDRMatcher.matches(address: address, cidr: cidr)
    }
    
    private static func matchIPv6CIDR(address: String, cidr: String) -> Bool {
        // Parse CIDR
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let prefixLength = Int(parts[1]),
              prefixLength >= 0 && prefixLength <= 128 else {
            return false
        }
        
        let networkAddress = String(parts[0])
        
        // Use Network framework for IPv6
        guard let addrIPv6 = IPv6Address(address),
              let netIPv6 = IPv6Address(networkAddress) else {
            return false
        }
        
        // Compare with prefix length
        return matchIPv6WithPrefix(address: addrIPv6, network: netIPv6, prefixLength: prefixLength)
    }
    
    private static func matchIPv6WithPrefix(address: IPv6Address, network: IPv6Address, prefixLength: Int) -> Bool {
        let addrBytes = address.rawValue
        let netBytes = network.rawValue
        
        // Compare full bytes
        let fullBytes = prefixLength / 8
        for i in 0..<fullBytes {
            if addrBytes[i] != netBytes[i] {
                return false
            }
        }
        
        // Compare remaining bits
        let remainingBits = prefixLength % 8
        if remainingBits > 0 && fullBytes < 16 {
            let mask = UInt8(0xFF << (8 - remainingBits))
            if (addrBytes[fullBytes] & mask) != (netBytes[fullBytes] & mask) {
                return false
            }
        }
        
        return true
    }
    
    private static func matchWildcard(address: String, pattern: String) -> Bool {
        // Use the new OpenSSH-compatible pattern matcher
        return PatternMatcher.match(address, pattern: pattern)
    }
    
    private static func isValidCIDR(_ cidr: String) -> Bool {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let prefixLength = Int(parts[1]) else {
            return false
        }
        
        let address = String(parts[0])
        
        // Check IPv4 CIDR
        if !address.contains(":") {
            guard prefixLength >= 0 && prefixLength <= 32 else {
                return false
            }
            return isValidIPAddress(address)
        }
        
        // Check IPv6 CIDR
        guard prefixLength >= 0 && prefixLength <= 128 else {
            return false
        }
        return isValidIPAddress(address)
    }
    
    private static func isValidIPAddress(_ address: String) -> Bool {
        // Try IPv4
        if IPv4Address(address) != nil {
            return true
        }
        
        // Try IPv6
        if IPv6Address(address) != nil {
            return true
        }
        
        return false
    }
}

// MARK: - Integration with NIOSSHCertifiedPublicKey

extension NIOSSHCertifiedPublicKey {
    /// Enhanced source address validation using OpenSSH-compatible matching
    public func validateSourceAddressEnhanced(_ clientAddress: String) throws {
        // Parse source addresses directly from critical options
        guard let sourceAddressString = self.criticalOptions["source-address"] else {
            return // No source address restriction
        }
        
        // Parse the allowed addresses
        let allowedAddresses = sourceAddressString.components(separatedBy: ",")
        
        guard !allowedAddresses.isEmpty else {
            return // No source address restriction
        }
        
        // Join the allowed addresses back into a comma-separated list
        let addressList = allowedAddresses.joined(separator: ",")
        
        // For certificates, OpenSSH uses strict CIDR matching (no wildcards)
        // This matches the behavior of addr_match_cidr_list() in auth-options.c
        let result = AddressValidator.matchCIDRList(clientAddress, against: addressList)
        
        switch result {
        case 1:
            // Positive match - allowed
            return
        case 0:
            // No match - not in allowed list
            throw SSHCertificateError.sourceAddressNotAllowed(clientAddress)
        case -1:
            // Invalid CIDR list format
            throw SSHCertificateError.parsingFailed("Invalid CIDR format in critical option")
        default:
            // Should not happen
            throw SSHCertificateError.parsingFailed("Unexpected validation result")
        }
    }
}