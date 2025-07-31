import Foundation

/// Protocol for platform-specific group membership checking
public protocol GroupMembershipChecker {
    func isUserInGroup(user: String, group: String) -> Bool
}

/// OpenSSH-compatible pattern matching implementation
/// Supports wildcard patterns with '*' and '?' characters
public struct PatternMatcher {
    
    /// Match result enumeration matching OpenSSH's return values
    public enum MatchResult: Int {
        case error = -2
        case negatedMatch = -1
        case noMatch = 0
        case match = 1
    }
    
    /// Matches a string against a pattern containing wildcards
    /// - Parameters:
    ///   - string: The string to test
    ///   - pattern: The pattern containing wildcards (* matches zero or more characters, ? matches exactly one)
    /// - Returns: true if the string matches the pattern
    public static func match(_ string: String, pattern: String) -> Bool {
        return matchPattern(string, pattern: pattern, stringIndex: string.startIndex, patternIndex: pattern.startIndex)
    }
    
    /// Recursive pattern matching implementation similar to OpenSSH's match_pattern()
    private static func matchPattern(_ string: String, pattern: String, stringIndex: String.Index, patternIndex: String.Index) -> Bool {
        var sIdx = stringIndex
        var pIdx = patternIndex
        
        while pIdx < pattern.endIndex {
            // Skip consecutive asterisks (optimization from OpenSSH)
            if pattern[pIdx] == "*" {
                var nextIdx = pattern.index(after: pIdx)
                while nextIdx < pattern.endIndex && pattern[nextIdx] == "*" {
                    nextIdx = pattern.index(after: nextIdx)
                }
                pIdx = nextIdx
                
                // If pattern ends with *, it matches everything remaining
                if pIdx >= pattern.endIndex {
                    return true
                }
                
                // Try to match the rest of the pattern from each possible position
                while sIdx <= string.endIndex {
                    if matchPattern(string, pattern: pattern, stringIndex: sIdx, patternIndex: pIdx) {
                        return true
                    }
                    if sIdx < string.endIndex {
                        sIdx = string.index(after: sIdx)
                    } else {
                        break
                    }
                }
                return false
            }
            
            // If we've reached the end of the string but not the pattern
            if sIdx >= string.endIndex {
                return false
            }
            
            // Match single character
            if pattern[pIdx] == "?" {
                // ? matches any single character
                sIdx = string.index(after: sIdx)
                pIdx = pattern.index(after: pIdx)
            } else if pattern[pIdx] == string[sIdx] {
                // Exact character match
                sIdx = string.index(after: sIdx)
                pIdx = pattern.index(after: pIdx)
            } else {
                // Characters don't match
                return false
            }
        }
        
        // Pattern exhausted - match only if string is also exhausted
        return sIdx >= string.endIndex
    }
    
    /// Matches a string against a comma-separated list of patterns
    /// Supports negation with '!' prefix
    /// - Parameters:
    ///   - string: The string to test
    ///   - patternList: Comma-separated list of patterns
    /// - Returns: MatchResult indicating match status
    public static func matchList(_ string: String, patternList: String) -> MatchResult {
        let patterns = patternList.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        
        // OpenSSH behavior: negated matches take precedence
        var gotPositive = false
        
        for pattern in patterns {
            guard !pattern.isEmpty else { continue }
            
            let isNegated = pattern.hasPrefix("!")
            let actualPattern = isNegated ? String(pattern.dropFirst()) : pattern
            
            if match(string, pattern: actualPattern) {
                if isNegated {
                    // Negative match returns immediately
                    return .negatedMatch
                } else {
                    // Remember positive match but keep checking
                    gotPositive = true
                }
            }
        }
        
        return gotPositive ? .match : .noMatch
    }
    
    /// Matches a hostname against a pattern (case-insensitive)
    /// - Parameters:
    ///   - hostname: The hostname to test
    ///   - pattern: The pattern to match against
    /// - Returns: true if the hostname matches
    public static func matchHostname(_ hostname: String, pattern: String) -> Bool {
        return match(hostname.lowercased(), pattern: pattern.lowercased())
    }
    
    /// Matches a hostname against a pattern list
    /// - Parameters:
    ///   - hostname: The hostname to test
    ///   - patternList: Comma-separated list of patterns
    /// - Returns: MatchResult indicating match status
    public static func matchHostnameList(_ hostname: String, patternList: String) -> MatchResult {
        let patterns = patternList.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        
        // OpenSSH behavior: negated matches take precedence
        var gotPositive = false
        
        for pattern in patterns {
            guard !pattern.isEmpty else { continue }
            
            let isNegated = pattern.hasPrefix("!")
            let actualPattern = isNegated ? String(pattern.dropFirst()) : pattern
            
            if matchHostname(hostname, pattern: actualPattern) {
                if isNegated {
                    // Negative match returns immediately
                    return .negatedMatch
                } else {
                    // Remember positive match but keep checking
                    gotPositive = true
                }
            }
        }
        
        return gotPositive ? .match : .noMatch
    }
    
    /// Matches a user name against a pattern
    /// OpenSSH treats '@' specially for domain matching
    /// - Parameters:
    ///   - user: The username to test
    ///   - pattern: The pattern to match against
    /// - Returns: true if the user matches
    public static func matchUser(_ user: String, pattern: String) -> Bool {
        // Check for domain-only pattern first (e.g., "@domain")
        if pattern.hasPrefix("@") && user.contains("@") {
            // Pattern like "@domain" matches any user at that domain
            let userDomain = user.split(separator: "@", maxSplits: 1).last.map(String.init) ?? ""
            let patternDomain = String(pattern.dropFirst())
            return match(userDomain, pattern: patternDomain)
        } else if pattern.contains("@") && user.contains("@") {
            // Full user@domain pattern
            return match(user, pattern: pattern)
        } else {
            // Simple user matching (no domain)
            let userName = user.split(separator: "@", maxSplits: 1).first.map(String.init) ?? user
            return match(userName, pattern: pattern)
        }
    }
    
    /// Default group membership checker (can be overridden for platform-specific behavior)
    public static var groupChecker: GroupMembershipChecker? = nil
    
    /// Matches a user against a pattern list that may include group patterns
    /// - Parameters:
    ///   - user: The username to test
    ///   - hostname: The hostname (optional)
    ///   - ipAddress: The IP address (optional)
    ///   - patternList: Comma-separated list of user/group patterns
    /// - Returns: MatchResult indicating match status
    public static func matchUserGroupPatternList(_ user: String, hostname: String?, ipAddress: String?, patternList: String) -> MatchResult {
        let patterns = patternList.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        
        // OpenSSH behavior: negated matches take precedence
        var gotPositive = false
        
        for pattern in patterns {
            guard !pattern.isEmpty else { continue }
            
            let isNegated = pattern.hasPrefix("!")
            let actualPattern = isNegated ? String(pattern.dropFirst()) : pattern
            
            var matched = false
            
            // Check for group pattern (starts with %)
            if actualPattern.hasPrefix("%") {
                let groupName = String(actualPattern.dropFirst())
                // Check group membership if we have a checker
                if let checker = groupChecker {
                    matched = checker.isUserInGroup(user: user, group: groupName)
                }
            }
            // Check for user@host pattern
            else if actualPattern.contains("@") && !actualPattern.hasPrefix("@") {
                // Split into user and host parts
                let parts = actualPattern.split(separator: "@", maxSplits: 1)
                if parts.count == 2 {
                    let userPart = String(parts[0])
                    let hostPart = String(parts[1])
                    
                    // Check if user matches
                    if match(user, pattern: userPart) {
                        // Check if host matches (against hostname or IP)
                        if let hostname = hostname, match(hostname, pattern: hostPart) {
                            matched = true
                        } else if let ipAddress = ipAddress, match(ipAddress, pattern: hostPart) {
                            matched = true
                        }
                    }
                }
            }
            // Regular user pattern
            else {
                matched = matchUser(user, pattern: actualPattern)
            }
            
            if matched {
                if isNegated {
                    // Negative match returns immediately
                    return .negatedMatch
                } else {
                    // Remember positive match but keep checking
                    gotPositive = true
                }
            }
        }
        
        return gotPositive ? .match : .noMatch
    }
    
    /// Matches an address against a pattern
    /// Supports both CIDR notation and wildcard patterns
    /// - Parameters:
    ///   - address: The address to test (IP or hostname)
    ///   - pattern: The pattern to match against
    /// - Returns: true if the address matches
    public static func matchAddress(_ address: String, pattern: String) -> Bool {
        // Try CIDR matching first for IP addresses
        if pattern.contains("/") && isIPAddress(address) {
            return matchCIDR(address, pattern: pattern)
        }
        
        // Fall back to wildcard pattern matching
        return match(address, pattern: pattern)
    }
    
    /// Helper to check if a string is an IP address
    private static func isIPAddress(_ string: String) -> Bool {
        // Simple check for IPv4 or IPv6
        let ipv4Pattern = #"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"#
        let ipv6Pattern = #"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"#
        
        return string.range(of: ipv4Pattern, options: .regularExpression) != nil ||
               string.range(of: ipv6Pattern, options: .regularExpression) != nil
    }
    
    /// CIDR pattern matching for IP addresses
    private static func matchCIDR(_ address: String, pattern: String) -> Bool {
        // Delegate to the existing CIDRMatcher implementation
        return CIDRMatcher.matches(address: address, cidr: pattern)
    }

    /// Matches a host and IP address against a pattern list
    /// This is critical for security - checks both hostname and IP address
    /// - Parameters:
    ///   - hostname: The hostname to test (can be nil)
    ///   - ipAddress: The IP address to test (can be nil)
    ///   - patternList: Comma-separated list of patterns
    /// - Returns: MatchResult indicating match status
    public static func matchHostAndIP(_ hostname: String?, ipAddress: String?, patternList: String) -> MatchResult {
        // OpenSSH behavior: check both hostname and IP against patterns
        let patterns = patternList.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        
        // Process all patterns, checking for negations
        var gotPositive = false
        
        for pattern in patterns {
            guard !pattern.isEmpty else { continue }
            
            let isNegated = pattern.hasPrefix("!")
            let actualPattern = isNegated ? String(pattern.dropFirst()) : pattern
            
            var matched = false
            
            // Check hostname if provided
            if let hostname = hostname {
                if matchHostname(hostname, pattern: actualPattern) {
                    matched = true
                }
            }
            
            // Check IP address if provided and not already matched
            if !matched, let ipAddress = ipAddress {
                if matchAddress(ipAddress, pattern: actualPattern) {
                    matched = true
                }
            }
            
            if matched {
                if isNegated {
                    // Negative match returns immediately
                    return .negatedMatch
                } else {
                    // Remember positive match but keep checking
                    gotPositive = true
                }
            }
        }
        
        return gotPositive ? .match : .noMatch
    }
    
    /// Matches against a list (used for algorithm negotiation)
    /// Returns the first item from the client list that matches any item in the server list
    /// - Parameters:
    ///   - clientList: Comma-separated list of client proposals
    ///   - serverList: Comma-separated list of server proposals
    /// - Returns: First matching item, or nil if no match
    public static func matchLists(_ clientList: String, serverList: String) -> String? {
        let clientItems = clientList.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        let serverItems = Set(serverList.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
        
        // Find first client item that exists in server list
        for clientItem in clientItems {
            if serverItems.contains(clientItem) {
                return clientItem
            }
        }
        
        return nil
    }
    
    /// Filters a list by removing items in the deny list
    /// - Parameters:
    ///   - list: Comma-separated list to filter
    ///   - denyList: Comma-separated list of patterns to deny
    /// - Returns: Filtered list as comma-separated string
    public static func filterDenyList(_ list: String, denyList: String) -> String {
        let items = list.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        let denyPatterns = denyList.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        
        let filtered = items.filter { item in
            // Check if item matches any deny pattern
            for denyPattern in denyPatterns {
                if match(item, pattern: denyPattern) {
                    return false // Deny this item
                }
            }
            return true // Keep this item
        }
        
        return filtered.joined(separator: ",")
    }
    
    /// Filters a list by keeping only items in the allow list
    /// - Parameters:
    ///   - list: Comma-separated list to filter
    ///   - allowList: Comma-separated list of patterns to allow
    /// - Returns: Filtered list as comma-separated string
    public static func filterAllowList(_ list: String, allowList: String) -> String {
        let items = list.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        let allowPatterns = allowList.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        
        let filtered = items.filter { item in
            // Check if item matches any allow pattern
            for allowPattern in allowPatterns {
                if match(item, pattern: allowPattern) {
                    return true // Allow this item
                }
            }
            return false // Deny this item
        }
        
        return filtered.joined(separator: ",")
    }
    
    // MARK: - Pattern Validation
    
    /// Maximum pattern size (matching OpenSSH's buffer limit)
    private static let maxPatternSize = 1024
    
    /// Validates pattern list size
    /// - Parameter patternList: Pattern list to validate
    /// - Returns: true if valid, false if too long
    public static func validatePatternListSize(_ patternList: String) -> Bool {
        // Check individual pattern sizes (OpenSSH uses 1024 byte buffer)
        let patterns = patternList.split(separator: ",")
        for pattern in patterns {
            if pattern.count >= maxPatternSize {
                return false
            }
        }
        return true
    }
    
    /// Valid characters for CIDR notation (matching OpenSSH)
    private static let validCIDRChars = CharacterSet(charactersIn: "0123456789abcdefABCDEF.:/")
    
    /// Validates CIDR list format
    /// - Parameter cidrList: CIDR list to validate
    /// - Returns: true if all entries are valid CIDR notation
    public static func validateCIDRList(_ cidrList: String) -> Bool {
        let entries = cidrList.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        
        for entry in entries {
            // Skip empty entries
            guard !entry.isEmpty else { continue }
            
            // Check for valid CIDR characters only
            if !entry.allSatisfy({ validCIDRChars.contains($0.unicodeScalars.first!) }) {
                return false
            }
            
            // Basic CIDR format validation
            if entry.contains("/") {
                let parts = entry.split(separator: "/")
                if parts.count != 2 {
                    return false
                }
                // Validate prefix length
                guard let prefixLen = Int(parts[1]) else {
                    return false
                }
                // Check prefix length bounds
                if entry.contains(":") {
                    // IPv6
                    if prefixLen < 0 || prefixLen > 128 {
                        return false
                    }
                } else {
                    // IPv4
                    if prefixLen < 0 || prefixLen > 32 {
                        return false
                    }
                }
            }
        }
        
        return true
    }
}

// MARK: - Convenience Extensions

public extension String {
    /// Checks if this string matches the given wildcard pattern
    func matches(pattern: String) -> Bool {
        return PatternMatcher.match(self, pattern: pattern)
    }
    
    /// Checks if this string matches any pattern in the comma-separated list
    func matches(patternList: String) -> PatternMatcher.MatchResult {
        return PatternMatcher.matchList(self, patternList: patternList)
    }
}