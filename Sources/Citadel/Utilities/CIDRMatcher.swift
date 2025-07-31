import Foundation

/// Simple CIDR matching utility
struct CIDRMatcher {
    
    /// Check if an IP address matches a CIDR pattern
    /// - Parameters:
    ///   - address: The IP address to check (e.g., "192.168.1.100")
    ///   - cidr: The CIDR pattern (e.g., "192.168.1.0/24")
    /// - Returns: true if the address matches the CIDR pattern
    static func matches(address: String, cidr: String) -> Bool {
        // Handle exact match
        if address == cidr {
            return true
        }
        
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