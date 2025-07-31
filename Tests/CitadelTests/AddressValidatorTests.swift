import XCTest
import NIOCore
@testable import Citadel

/// Tests for AddressValidator - OpenSSH-compatible address matching
final class AddressValidatorTests: XCTestCase {
    
    // MARK: - IPv4 CIDR Tests
    
    func testIPv4CIDRMatching() {
        // Test /24 network
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: "192.168.1.0/24"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.255", against: "192.168.1.0/24"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.2.1", against: "192.168.1.0/24"), 0)
        
        // Test /32 (single host)
        XCTAssertEqual(AddressValidator.matchAddressList("10.0.0.1", against: "10.0.0.1/32"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("10.0.0.2", against: "10.0.0.1/32"), 0)
        
        // Test /16 network
        XCTAssertEqual(AddressValidator.matchAddressList("172.16.0.1", against: "172.16.0.0/16"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("172.16.255.255", against: "172.16.0.0/16"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("172.17.0.1", against: "172.16.0.0/16"), 0)
    }
    
    // MARK: - IPv6 CIDR Tests
    
    func testIPv6CIDRMatching() {
        // Test /64 network
        XCTAssertEqual(AddressValidator.matchAddressList("2001:db8:85a3::8a2e:370:7334", against: "2001:db8:85a3::/64"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("2001:db8:85a3::1", against: "2001:db8:85a3::/64"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("2001:db8:85a4::1", against: "2001:db8:85a3::/64"), 0)
        
        // Test /128 (single host)
        XCTAssertEqual(AddressValidator.matchAddressList("::1", against: "::1/128"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("::2", against: "::1/128"), 0)
    }
    
    // MARK: - Negation Tests
    
    func testNegatedPatterns() {
        // Single negation
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: "!192.168.1.100"), -1)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.101", against: "!192.168.1.100"), 0)
        
        // Negated CIDR
        XCTAssertEqual(AddressValidator.matchAddressList("10.0.0.5", against: "!10.0.0.0/24"), -1)
        XCTAssertEqual(AddressValidator.matchAddressList("10.1.0.5", against: "!10.0.0.0/24"), 0)
    }
    
    // MARK: - Multiple Pattern Tests
    
    func testMultiplePatterns() {
        // Allow from multiple networks
        let list1 = "192.168.1.0/24,10.0.0.0/8"
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: list1), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("10.5.5.5", against: list1), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("172.16.0.1", against: list1), 0)
        
        // Mixed allow and deny - order matters, first match wins
        let list2 = "192.168.0.0/16,!192.168.1.100"
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.2.1", against: list2), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: list2), 1) // Matched by first pattern
        
        // Order matters - negation first
        let list3 = "!192.168.1.100,192.168.1.0/24"
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: list3), -1) // Denied first
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.101", against: list3), 1)
    }
    
    // MARK: - Wildcard Pattern Tests
    
    func testWildcardPatterns() {
        // Basic wildcards
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: "192.168.*.*"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.255.255", against: "192.168.*.*"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("192.169.1.1", against: "192.168.*.*"), 0)
        
        // Single octet wildcard
        XCTAssertEqual(AddressValidator.matchAddressList("10.0.0.5", against: "10.0.0.*"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("10.0.1.5", against: "10.0.0.*"), 0)
        
        // Multiple wildcards
        XCTAssertEqual(AddressValidator.matchAddressList("172.16.5.100", against: "172.*.5.*"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("172.32.5.200", against: "172.*.5.*"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("172.16.6.100", against: "172.*.5.*"), 0)
    }
    
    // MARK: - Exact Match Tests
    
    func testExactMatches() {
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.1", against: "192.168.1.1"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.2", against: "192.168.1.1"), 0)
        
        // IPv6 exact match
        XCTAssertEqual(AddressValidator.matchAddressList("2001:db8::1", against: "2001:db8::1"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("2001:db8::2", against: "2001:db8::1"), 0)
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
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.1", against: "192.168.1.1,"), 1)
        
        // Whitespace handling
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.1", against: " 192.168.1.1 "), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.1", against: "192.168.1.0/24, 10.0.0.1"), 1)
        
        // All addresses (/0)
        XCTAssertEqual(AddressValidator.matchAddressList("1.2.3.4", against: "0.0.0.0/0"), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.1", against: "0.0.0.0/0"), 1)
    }
    
    // MARK: - Complex Pattern Tests
    
    func testComplexPatternCombinations() {
        // Test OpenSSH behavior: first match wins
        let complexList = "192.168.0.0/16,!192.168.1.100,!192.168.2.0/24,10.0.0.0/8"
        
        // Allowed in 192.168.0.0/16 (first match)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.3.1", against: complexList), 1)
        
        // Matched by first pattern (192.168.0.0/16) before negation
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: complexList), 1)
        
        // Also matched by first pattern before negation
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.2.50", against: complexList), 1)
        
        // Allowed in second network
        XCTAssertEqual(AddressValidator.matchAddressList("10.5.5.5", against: complexList), 1)
        
        // Not in any allowed network
        XCTAssertEqual(AddressValidator.matchAddressList("172.16.0.1", against: complexList), 0)
        
        // Test with negations first
        let negFirstList = "!192.168.1.100,!192.168.2.0/24,192.168.0.0/16,10.0.0.0/8"
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.1.100", against: negFirstList), -1)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.2.50", against: negFirstList), -1)
        XCTAssertEqual(AddressValidator.matchAddressList("192.168.3.1", against: negFirstList), 1)
    }
    
    func testRealWorldCertificateScenarios() {
        // Scenario 1: Corporate network - order matters
        let corpNetwork = "10.0.0.0/8,172.16.0.0/12,!10.99.99.0/24"
        XCTAssertEqual(AddressValidator.matchAddressList("10.1.2.3", against: corpNetwork), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("172.20.5.10", against: corpNetwork), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("10.99.99.50", against: corpNetwork), 1) // Matched by 10.0.0.0/8 first
        
        // With negation first
        let corpNetworkNegFirst = "!10.99.99.0/24,10.0.0.0/8,172.16.0.0/12"
        XCTAssertEqual(AddressValidator.matchAddressList("10.99.99.50", against: corpNetworkNegFirst), -1)
        XCTAssertEqual(AddressValidator.matchAddressList("10.1.2.3", against: corpNetworkNegFirst), 1)
        
        // Scenario 2: Bastion host access pattern
        let bastionAccess = "203.0.113.5,198.51.100.0/24,!198.51.100.200"
        XCTAssertEqual(AddressValidator.matchAddressList("203.0.113.5", against: bastionAccess), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("198.51.100.50", against: bastionAccess), 1)
        XCTAssertEqual(AddressValidator.matchAddressList("198.51.100.200", against: bastionAccess), 1) // Matched by /24 first
        
        // With negation first
        let bastionNegFirst = "!198.51.100.200,203.0.113.5,198.51.100.0/24"
        XCTAssertEqual(AddressValidator.matchAddressList("198.51.100.200", against: bastionNegFirst), -1)
    }
}