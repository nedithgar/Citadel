import XCTest
import NIOCore
@testable import Citadel

/// Tests for AddressValidator - OpenSSH-compatible address matching
final class AddressValidatorTests: XCTestCase {
    
    // MARK: - Constants for AddressValidator return values
    
    /// Address matches the pattern
    private static let MATCH = 1
    
    /// Address does not match the pattern
    private static let NO_MATCH = 0
    
    /// Address is explicitly denied (negated match)
    private static let NEGATED_MATCH = -1
    
    /// Invalid list format or error
    private static let ERROR = -1
    
    // MARK: - IPv4 CIDR Tests
    
    func testIPv4CIDRMatching() {
        // Test /24 network
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: "192.168.1.0/24"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.255", against: "192.168.1.0/24"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.2.1", against: "192.168.1.0/24"), Self.NO_MATCH)
        
        // Test /32 (single host)
        XCTAssertEqual(AddressValidator.matchAddressList("10.0.0.1", against: "10.0.0.1/32"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("10.0.0.2", against: "10.0.0.1/32"), Self.NO_MATCH)
        
        // Test /16 network
        XCTAssertEqual(AddressValidator.matchAddressList("172.16.0.1", against: "172.16.0.0/16"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("172.16.255.255", against: "172.16.0.0/16"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("172.17.0.1", against: "172.16.0.0/16"), Self.NO_MATCH)
    }
    
    // MARK: - IPv6 CIDR Tests
    
    func testIPv6CIDRMatching() {
        // Test /64 network
        XCTAssertEqual(AddressValidator.matchAddressList("2001:db8:85a3::8a2e:370:7334", against: "2001:db8:85a3::/64"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("2001:db8:85a3::1", against: "2001:db8:85a3::/64"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("2001:db8:85a4::1", against: "2001:db8:85a3::/64"), Self.NO_MATCH)
        
        // Test /128 (single host)
        XCTAssertEqual(AddressValidator.matchAddressList("::1", against: "::1/128"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("::2", against: "::1/128"), Self.NO_MATCH)
    }
    
    // MARK: - Negation Tests
    
    func testNegatedPatterns() {
        // Single negation
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: "!192.168.1.100"), Self.NEGATED_MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.101", against: "!192.168.1.100"), Self.NO_MATCH)
        
        // Negated CIDR
        XCTAssertEqual(AddressValidator.matchAddressList("10.0.0.5", against: "!10.0.0.0/24"), Self.NEGATED_MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("10.1.0.5", against: "!10.0.0.0/24"), Self.NO_MATCH)
    }
    
    // MARK: - Multiple Pattern Tests
    
    func testMultiplePatterns() {
        // Allow from multiple networks
        let list1 = "192.168.1.0/24,10.0.0.0/8"
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: list1), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("10.5.5.5", against: list1), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("172.16.0.1", against: list1), Self.NO_MATCH)
        
        // Mixed allow and deny - order matters, first match wins
        let list2 = "192.168.0.0/16,!192.168.1.100"
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.2.1", against: list2), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: list2), Self.MATCH) // Matched by first pattern
        
        // Order matters - negation first
        let list3 = "!192.168.1.100,192.168.1.0/24"
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: list3), Self.NEGATED_MATCH) // Denied first
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.101", against: list3), Self.MATCH)
    }
    
    // MARK: - Wildcard Pattern Tests
    
    func testWildcardPatterns() {
        // Basic wildcards
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: "192.168.*.*"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.255.255", against: "192.168.*.*"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("192.169.1.1", against: "192.168.*.*"), Self.NO_MATCH)
        
        // Single octet wildcard
        XCTAssertEqual(AddressValidator.matchAddressList("10.0.0.5", against: "10.0.0.*"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("10.0.1.5", against: "10.0.0.*"), Self.NO_MATCH)
        
        // Multiple wildcards
        XCTAssertEqual(AddressValidator.matchAddressList("172.16.5.100", against: "172.*.5.*"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("172.32.5.200", against: "172.*.5.*"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("172.16.6.100", against: "172.*.5.*"), Self.NO_MATCH)
    }
    
    // MARK: - Exact Match Tests
    
    func testExactMatches() {
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.1", against: "192.168.1.1"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.2", against: "192.168.1.1"), Self.NO_MATCH)
        
        // IPv6 exact match
        XCTAssertEqual(AddressValidator.matchAddressList("2001:db8::1", against: "2001:db8::1"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("2001:db8::2", against: "2001:db8::1"), Self.NO_MATCH)
    }
    
    // MARK: - Validation Tests
    
    func testAddressListValidation() {
        // Valid lists
        XCTAssertTrue(AddressValidator.validateAddressList("192.168.1.0/24"))
        XCTAssertTrue(AddressValidator.validateAddressList("192.168.1.1"))
        XCTAssertTrue(AddressValidator.validateAddressList("192.168.1.0/24,10.0.0.1"))
        XCTAssertTrue(AddressValidator.validateAddressList("!192.168.1.100,192.168.1.0/24"))
        XCTAssertTrue(AddressValidator.validateAddressList("192.168.*.*"))
        XCTAssertTrue(AddressValidator.validateAddressList("2001:db8::/32"))
        
        // Invalid lists
        XCTAssertFalse(AddressValidator.validateAddressList("")) // Empty
        XCTAssertFalse(AddressValidator.validateAddressList("192.168.1.0/33")) // Invalid prefix
        XCTAssertFalse(AddressValidator.validateAddressList("192.168.1.256")) // Invalid IP
        XCTAssertTrue(AddressValidator.validateAddressList("192.168.1.0/24,")) // Trailing comma is OK in OpenSSH
        XCTAssertTrue(AddressValidator.validateAddressList("192.168.1.0/24,,10.0.0.1")) // Empty entries are skipped
    }
    
    // MARK: - Edge Cases
    
    func testEdgeCases() {
        // Trailing comma is allowed in OpenSSH (empty pattern is skipped)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.1", against: "192.168.1.1,"), Self.MATCH)
        
        // Whitespace handling
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.1", against: " 192.168.1.1 "), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.1", against: "192.168.1.0/24, 10.0.0.1"), Self.MATCH)
        
        // All addresses (/0)
        XCTAssertEqual(AddressValidator.matchAddressList("1.2.3.4", against: "0.0.0.0/0"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.1", against: "0.0.0.0/0"), Self.MATCH)
    }
    
    // MARK: - Complex Pattern Tests
    
    func testComplexPatternCombinations() {
        // Test OpenSSH behavior: first match wins
        let complexList = "192.168.0.0/16,!192.168.1.100,!192.168.2.0/24,10.0.0.0/8"
        
        // Allowed in 192.168.0.0/16 (first match)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.3.1", against: complexList), Self.MATCH)
        
        // Matched by first pattern (192.168.0.0/16) before negation
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: complexList), Self.MATCH)
        
        // Also matched by first pattern before negation
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.2.50", against: complexList), Self.MATCH)
        
        // Allowed in second network
        XCTAssertEqual(AddressValidator.matchAddressList("10.5.5.5", against: complexList), Self.MATCH)
        
        // Not in any allowed network
        XCTAssertEqual(AddressValidator.matchAddressList("172.16.0.1", against: complexList), Self.NO_MATCH)
        
        // Test with negations first
        let negFirstList = "!192.168.1.100,!192.168.2.0/24,192.168.0.0/16,10.0.0.0/8"
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: negFirstList), Self.NEGATED_MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.2.50", against: negFirstList), Self.NEGATED_MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.3.1", against: negFirstList), Self.MATCH)
    }
    
    func testRealWorldCertificateScenarios() {
        // Scenario 1: Corporate network - order matters
        let corpNetwork = "10.0.0.0/8,172.16.0.0/12,!10.99.99.0/24"
        XCTAssertEqual(AddressValidator.matchAddressList("10.1.2.3", against: corpNetwork), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("172.20.5.10", against: corpNetwork), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("10.99.99.50", against: corpNetwork), Self.MATCH) // Matched by 10.0.0.0/8 first
        
        // With negation first
        let corpNetworkNegFirst = "!10.99.99.0/24,10.0.0.0/8,172.16.0.0/12"
        XCTAssertEqual(AddressValidator.matchAddressList("10.99.99.50", against: corpNetworkNegFirst), Self.NEGATED_MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("10.1.2.3", against: corpNetworkNegFirst), Self.MATCH)
        
        // Scenario 2: Bastion host access pattern
        let bastionAccess = "203.0.113.5,198.51.100.0/24,!198.51.100.200"
        XCTAssertEqual(AddressValidator.matchAddressList("203.0.113.5", against: bastionAccess), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("198.51.100.50", against: bastionAccess), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchAddressList("198.51.100.200", against: bastionAccess), Self.MATCH) // Matched by /24 first
        
        // With negation first
        let bastionNegFirst = "!198.51.100.200,203.0.113.5,198.51.100.0/24"
        XCTAssertEqual(AddressValidator.matchAddressList("198.51.100.200", against: bastionNegFirst), Self.NEGATED_MATCH)
    }
    
    // MARK: - Strict CIDR List Tests (like OpenSSH's addr_match_cidr_list)
    
    func testStrictCIDRMatching() {
        // Valid CIDR matches
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "192.168.1.0/24"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchCIDRList("10.0.0.5", against: "10.0.0.0/8"), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchCIDRList("2001:db8::1", against: "2001:db8::/32"), Self.MATCH)
        
        // No match
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.2.100", against: "192.168.1.0/24"), Self.NO_MATCH)
        XCTAssertEqual(AddressValidator.matchCIDRList("10.0.0.5", against: "192.168.1.0/24"), Self.NO_MATCH)
        
        // Validation only (nil address)
        XCTAssertEqual(AddressValidator.matchCIDRList(nil, against: "192.168.1.0/24"), Self.NO_MATCH)
        XCTAssertEqual(AddressValidator.matchCIDRList(nil, against: "192.168.1.0/24,10.0.0.0/8"), Self.NO_MATCH)
        
        // Invalid formats return -1
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "192.168.1.*"), Self.ERROR) // Wildcards not allowed
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "!192.168.1.0/24"), Self.ERROR) // Negation not allowed
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "192.168.1.100"), Self.MATCH) // Plain IP allowed (OpenSSH behavior)
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "192.168.1.0/33"), Self.ERROR) // Invalid prefix
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "invalid.address/24"), Self.ERROR) // Invalid address
    }
    
    func testStrictCIDRValidation() {
        // Valid CIDR lists
        XCTAssertTrue(AddressValidator.validateCIDRList("192.168.1.0/24"))
        XCTAssertTrue(AddressValidator.validateCIDRList("192.168.1.0/24,10.0.0.0/8"))
        XCTAssertTrue(AddressValidator.validateCIDRList("2001:db8::/32"))
        XCTAssertTrue(AddressValidator.validateCIDRList("0.0.0.0/0")) // Allow all IPv4
        XCTAssertTrue(AddressValidator.validateCIDRList("::/0")) // Allow all IPv6
        
        // Invalid CIDR lists
        XCTAssertFalse(AddressValidator.validateCIDRList("")) // Empty
        XCTAssertTrue(AddressValidator.validateCIDRList("192.168.1.100")) // Plain IP allowed (OpenSSH behavior)
        XCTAssertFalse(AddressValidator.validateCIDRList("192.168.1.*")) // Wildcards not allowed
        XCTAssertFalse(AddressValidator.validateCIDRList("!192.168.1.0/24")) // Negation not allowed
        XCTAssertFalse(AddressValidator.validateCIDRList("192.168.1.0/33")) // Invalid prefix
        XCTAssertFalse(AddressValidator.validateCIDRList("192.168.1.0/24,,10.0.0.0/8")) // Empty entries not allowed
        XCTAssertFalse(AddressValidator.validateCIDRList("192.168.1.0/24,")) // Trailing comma creates empty entry
        XCTAssertFalse(AddressValidator.validateCIDRList("2001:db8::/129")) // Invalid IPv6 prefix
        XCTAssertFalse(AddressValidator.validateCIDRList("invalid.address/24")) // Invalid address
        XCTAssertFalse(AddressValidator.validateCIDRList("192.168.1.0/24,invalid-chars!@#")) // Invalid characters
    }
    
    func testCertificateSourceAddressValidation() {
        // Test realistic certificate source-address scenarios
        let corporateNetwork = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
        XCTAssertEqual(AddressValidator.matchCIDRList("10.5.5.5", against: corporateNetwork), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchCIDRList("172.20.1.100", against: corporateNetwork), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.100.50", against: corporateNetwork), Self.MATCH)
        XCTAssertEqual(AddressValidator.matchCIDRList("203.0.113.5", against: corporateNetwork), Self.NO_MATCH) // Public IP
        
        // Validation mode (used when parsing certificates)
        XCTAssertEqual(AddressValidator.matchCIDRList(nil, against: corporateNetwork), Self.NO_MATCH)
        XCTAssertTrue(AddressValidator.validateCIDRList(corporateNetwork))
        
        // Invalid certificate source-address patterns should be rejected
        let invalidPattern = "10.0.0.0/8,192.168.*.* " // Contains wildcard
        XCTAssertEqual(AddressValidator.matchCIDRList(nil, against: invalidPattern), Self.ERROR)
        XCTAssertFalse(AddressValidator.validateCIDRList(invalidPattern))
    }
}