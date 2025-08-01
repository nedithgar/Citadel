import Foundation

/// Simple CIDR matching utility supporting both IPv4 and IPv6
struct CIDRMatcher {
    
    /// Check if an IP address matches a CIDR pattern
    /// - Parameters:
    ///   - address: The IP address to check (e.g., "192.168.1.100" or "2001:db8::1")
    ///   - cidr: The CIDR pattern (e.g., "192.168.1.0/24" or "2001:db8::/32")
    /// - Returns: true if the address matches the CIDR pattern
    static func matches(address: String, cidr: String) -> Bool {
        // Handle exact match
        if address == cidr {
            return true
        }
        
        // Check if it's IPv6
        if address.contains(":") || cidr.contains(":") {
            return matchesIPv6(address: address, cidr: cidr)
        }
        
        // IPv4 matching
        return matchesIPv4(address: address, cidr: cidr)
    }
    
    /// IPv4 CIDR matching
    private static func matchesIPv4(address: String, cidr: String) -> Bool {
        // Parse CIDR notation
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let prefixLength = Int(parts[1]),
              prefixLength >= 0 && prefixLength <= 32 else {
            return false
        }
        
        let networkAddress = String(parts[0])
        
        // Convert IP addresses to 32-bit integers
        guard let addressInt = ipToUInt32(address),
              let networkInt = ipToUInt32(networkAddress) else {
            return false
        }
        
        // Create mask for the prefix length
        let mask: UInt32
        switch prefixLength {
        case 0:
            mask = 0
        case 32:
            mask = UInt32.max
        case 1...31:
            mask = UInt32.max << (32 - prefixLength)
        default:
            // This should never happen due to the guard above, but handle defensively
            return false
        }
        
        // Check if the address is in the network
        return (addressInt & mask) == (networkInt & mask)
    }
    
    /// IPv6 CIDR matching
    private static func matchesIPv6(address: String, cidr: String) -> Bool {
        // Parse CIDR notation
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let prefixLength = Int(parts[1]),
              prefixLength >= 0 && prefixLength <= 128 else {
            return false
        }
        
        let networkAddress = String(parts[0])
        
        // Parse IPv6 addresses
        guard let addrBytes = parseIPv6(address),
              let netBytes = parseIPv6(networkAddress) else {
            return false
        }
        
        // Compare with prefix length
        return matchIPv6WithPrefix(addressBytes: addrBytes, networkBytes: netBytes, prefixLength: prefixLength)
    }
    
    /// Compare IPv6 addresses with prefix length
    private static func matchIPv6WithPrefix(addressBytes: [UInt8], networkBytes: [UInt8], prefixLength: Int) -> Bool {
        guard addressBytes.count == 16 && networkBytes.count == 16 else {
            return false
        }
        
        // Compare full bytes
        let fullBytes = prefixLength / 8
        for i in 0..<fullBytes {
            if addressBytes[i] != networkBytes[i] {
                return false
            }
        }
        
        // Compare remaining bits
        let remainingBits = prefixLength % 8
        if remainingBits > 0 && fullBytes < 16 {
            let mask = UInt8(0xFF << (8 - remainingBits))
            if (addressBytes[fullBytes] & mask) != (networkBytes[fullBytes] & mask) {
                return false
            }
        }
        
        return true
    }
    
    /// Convert an IPv4 address string to a 32-bit integer
    static func ipToUInt32(_ ip: String) -> UInt32? {
        let parts = ip.split(separator: ".")
        guard parts.count == 4 else { return nil }
        
        var result: UInt32 = 0
        for part in parts {
            guard let octet = UInt8(part) else { return nil }
            result = (result << 8) | UInt32(octet)
        }
        
        return result
    }
    
    /// Parse an IPv6 address string to bytes
    static func parseIPv6(_ address: String) -> [UInt8]? {
        var normalizedAddress = address
        
        // Handle IPv6 zone ID (e.g., fe80::1%eth0)
        if let percentIndex = address.firstIndex(of: "%") {
            normalizedAddress = String(address[..<percentIndex])
        }
        
        // Handle IPv6 with embedded IPv4 (e.g., ::ffff:192.168.1.1)
        if let lastColon = normalizedAddress.lastIndex(of: ":"),
           let dotIndex = normalizedAddress.firstIndex(of: "."),
           dotIndex > lastColon {
            // Extract the IPv4 part
            let ipv4Part = String(normalizedAddress[normalizedAddress.index(after: lastColon)...])
            guard let ipv4Int = ipToUInt32(ipv4Part) else { return nil }
            
            // Convert IPv4 to bytes and append to IPv6 part
            let ipv6Part = String(normalizedAddress[..<normalizedAddress.index(after: lastColon)])
            guard var bytes = parseIPv6(ipv6Part + "0:0") else { return nil }
            
            // Replace last 4 bytes with IPv4 address
            bytes[12] = UInt8((ipv4Int >> 24) & 0xFF)
            bytes[13] = UInt8((ipv4Int >> 16) & 0xFF)
            bytes[14] = UInt8((ipv4Int >> 8) & 0xFF)
            bytes[15] = UInt8(ipv4Int & 0xFF)
            
            return bytes
        }
        
        // Split into groups
        let groups = normalizedAddress.split(separator: ":", omittingEmptySubsequences: false)
        
        // Handle :: notation
        var expandedGroups: [String] = []
        var foundDoubleColon = false
        var doubleColonIndex = -1
        
        // Find where the :: is located
        for (index, group) in groups.enumerated() {
            if group.isEmpty && !foundDoubleColon {
                foundDoubleColon = true
                doubleColonIndex = index
            }
        }
        
        if foundDoubleColon {
            // Count non-empty groups
            let nonEmptyCount = groups.filter { !$0.isEmpty }.count
            let zerosNeeded = 8 - nonEmptyCount
            
            // Expand the groups
            for (index, group) in groups.enumerated() {
                if index == doubleColonIndex {
                    // Insert zeros for ::
                    for _ in 0..<zerosNeeded {
                        expandedGroups.append("0")
                    }
                } else if !group.isEmpty {
                    expandedGroups.append(String(group))
                }
            }
        } else {
            // No :: found, use groups as-is
            expandedGroups = groups.map { String($0) }
        }
        
        // Must have exactly 8 groups
        guard expandedGroups.count == 8 else { return nil }
        
        // Convert to bytes
        var bytes: [UInt8] = []
        for group in expandedGroups {
            guard let value = UInt16(group, radix: 16) else { return nil }
            bytes.append(UInt8((value >> 8) & 0xFF))
            bytes.append(UInt8(value & 0xFF))
        }
        
        return bytes
    }
    
    /// Validate an IPv4 address format
    static func isValidIPv4(_ address: String) -> Bool {
        return ipToUInt32(address) != nil
    }
    
    /// Validate an IPv6 address format
    static func isValidIPv6(_ address: String) -> Bool {
        return parseIPv6(address) != nil
    }
}