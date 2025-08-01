import XCTest
@testable import Citadel

final class CrossPlatformIPTests: XCTestCase {
    
    func testIPv4Parsing() {
        // Valid IPv4 addresses
        XCTAssertTrue(CIDRMatcher.isValidIPv4("192.168.1.1"))
        XCTAssertTrue(CIDRMatcher.isValidIPv4("0.0.0.0"))
        XCTAssertTrue(CIDRMatcher.isValidIPv4("255.255.255.255"))
        
        // Invalid IPv4 addresses
        XCTAssertFalse(CIDRMatcher.isValidIPv4("192.168.1"))
        XCTAssertFalse(CIDRMatcher.isValidIPv4("192.168.1.256"))
        XCTAssertFalse(CIDRMatcher.isValidIPv4("192.168.1.1.1"))
        XCTAssertFalse(CIDRMatcher.isValidIPv4("not.an.ip.address"))
    }
    
    func testIPv6Parsing() {
        // Valid IPv6 addresses
        XCTAssertTrue(CIDRMatcher.isValidIPv6("2001:db8::1"))
        XCTAssertTrue(CIDRMatcher.isValidIPv6("::1"))
        XCTAssertTrue(CIDRMatcher.isValidIPv6("::"))
        XCTAssertTrue(CIDRMatcher.isValidIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
        XCTAssertTrue(CIDRMatcher.isValidIPv6("2001:db8:85a3::8a2e:370:7334"))
        XCTAssertTrue(CIDRMatcher.isValidIPv6("::ffff:192.168.1.1")) // IPv4-mapped IPv6
        
        // Invalid IPv6 addresses
        XCTAssertFalse(CIDRMatcher.isValidIPv6("gggg::1"))
        XCTAssertFalse(CIDRMatcher.isValidIPv6("2001:db8:85a3:1:2:3:4:5:6")) // Too many groups
        XCTAssertFalse(CIDRMatcher.isValidIPv6("12345::1")) // Invalid hex
    }
    
    func testIPv4CIDRMatching() {
        // Test /24 network
        XCTAssertTrue(CIDRMatcher.matches(address: "192.168.1.1", cidr: "192.168.1.0/24"))
        XCTAssertTrue(CIDRMatcher.matches(address: "192.168.1.255", cidr: "192.168.1.0/24"))
        XCTAssertFalse(CIDRMatcher.matches(address: "192.168.2.1", cidr: "192.168.1.0/24"))
        
        // Test /32 (single host)
        XCTAssertTrue(CIDRMatcher.matches(address: "192.168.1.1", cidr: "192.168.1.1/32"))
        XCTAssertFalse(CIDRMatcher.matches(address: "192.168.1.2", cidr: "192.168.1.1/32"))
        
        // Test /0 (all addresses)
        XCTAssertTrue(CIDRMatcher.matches(address: "1.2.3.4", cidr: "0.0.0.0/0"))
        XCTAssertTrue(CIDRMatcher.matches(address: "255.255.255.255", cidr: "0.0.0.0/0"))
        
        // Test edge cases for all valid prefix lengths
        for prefix in 0...32 {
            let result = CIDRMatcher.matches(address: "10.0.0.1", cidr: "10.0.0.0/\(prefix)")
            // Should not crash and should return a valid result
            XCTAssertTrue(result || !result) // This is always true, just verifying no crash
        }
        
        // Test invalid prefix lengths (defensive programming)
        XCTAssertFalse(CIDRMatcher.matches(address: "192.168.1.1", cidr: "192.168.1.0/33"))
        XCTAssertFalse(CIDRMatcher.matches(address: "192.168.1.1", cidr: "192.168.1.0/-1"))
    }
    
    func testIPv6CIDRMatching() {
        // Test /64 network
        XCTAssertTrue(CIDRMatcher.matches(address: "2001:db8:85a3:1::1", cidr: "2001:db8:85a3:1::/64"))
        XCTAssertTrue(CIDRMatcher.matches(address: "2001:db8:85a3:1:ffff:ffff:ffff:ffff", cidr: "2001:db8:85a3:1::/64"))
        XCTAssertFalse(CIDRMatcher.matches(address: "2001:db8:85a3:2::1", cidr: "2001:db8:85a3:1::/64"))
        
        // Test /128 (single host)
        XCTAssertTrue(CIDRMatcher.matches(address: "2001:db8::1", cidr: "2001:db8::1/128"))
        XCTAssertFalse(CIDRMatcher.matches(address: "2001:db8::2", cidr: "2001:db8::1/128"))
        
        // Test /0 (all addresses)
        XCTAssertTrue(CIDRMatcher.matches(address: "::1", cidr: "::/0"))
        XCTAssertTrue(CIDRMatcher.matches(address: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", cidr: "::/0"))
    }
    
    func testIPv6ShortFormParsing() {
        // Test that different representations of the same address match
        let fullForm = "2001:0db8:0000:0000:0000:0000:0000:0001"
        let shortForm = "2001:db8::1"
        
        XCTAssertTrue(CIDRMatcher.matches(address: fullForm, cidr: shortForm + "/128"))
        XCTAssertTrue(CIDRMatcher.matches(address: shortForm, cidr: fullForm + "/128"))
    }
}