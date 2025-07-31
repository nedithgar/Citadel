import Foundation
import Network

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
        if prefixLength == 0 {
            mask = 0
        } else if prefixLength == 32 {
            mask = UInt32.max
        } else {
            mask = UInt32.max << (32 - prefixLength)
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
        
        // Use Network framework for IPv6
        guard let addrIPv6 = IPv6Address(address),
              let netIPv6 = IPv6Address(networkAddress) else {
            return false
        }
        
        // Compare with prefix length
        return matchIPv6WithPrefix(address: addrIPv6, network: netIPv6, prefixLength: prefixLength)
    }
    
    /// Compare IPv6 addresses with prefix length
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
    
    /// Convert an IPv4 address string to a 32-bit integer
    private static func ipToUInt32(_ ip: String) -> UInt32? {
        let parts = ip.split(separator: ".")
        guard parts.count == 4 else { return nil }
        
        var result: UInt32 = 0
        for part in parts {
            guard let octet = UInt8(part) else { return nil }
            result = (result << 8) | UInt32(octet)
        }
        
        return result
    }
}