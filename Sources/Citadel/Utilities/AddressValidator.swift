import Foundation
import Network

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
        // Convert wildcard pattern to regex
        let escapedPattern = NSRegularExpression.escapedPattern(for: pattern)
        let regexPattern = "^" + escapedPattern.replacingOccurrences(of: "\\*", with: "[0-9]+") + "$"
        
        guard let regex = try? NSRegularExpression(pattern: regexPattern, options: []) else {
            return false
        }
        
        let range = NSRange(location: 0, length: address.utf16.count)
        return regex.firstMatch(in: address, options: [], range: range) != nil
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

// MARK: - Integration with SSHCertificate

extension SSHCertificate {
    /// Enhanced source address validation using OpenSSH-compatible matching
    public func validateSourceAddressEnhanced(_ clientAddress: String) throws {
        let constraints = try CertificateConstraints(from: self)
        
        guard let allowedAddresses = constraints.sourceAddresses, !allowedAddresses.isEmpty else {
            return // No source address restriction
        }
        
        // Join the allowed addresses back into a comma-separated list
        let addressList = allowedAddresses.joined(separator: ",")
        
        // Use the enhanced validator
        let result = AddressValidator.matchAddressList(clientAddress, against: addressList)
        
        switch result {
        case 1:
            // Positive match - allowed
            return
        case -1:
            // Negated match - explicitly denied
            throw SSHCertificateError.sourceAddressNotAllowed(
                clientAddress: clientAddress,
                allowedAddresses: allowedAddresses
            )
        case 0:
            // No match - not in allowed list
            throw SSHCertificateError.sourceAddressNotAllowed(
                clientAddress: clientAddress,
                allowedAddresses: allowedAddresses
            )
        default:
            // Invalid list format
            throw SSHCertificateError.invalidCriticalOption
        }
    }
}