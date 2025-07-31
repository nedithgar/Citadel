import XCTest
@testable import Citadel

final class PatternMatcherTests: XCTestCase {
    
    // MARK: - Basic Pattern Matching Tests
    
    func testExactMatch() {
        XCTAssertTrue(PatternMatcher.match("test", pattern: "test"))
        XCTAssertFalse(PatternMatcher.match("test", pattern: "Test"))
        XCTAssertFalse(PatternMatcher.match("test", pattern: "testing"))
        XCTAssertFalse(PatternMatcher.match("testing", pattern: "test"))
    }
    
    func testEmptyPatterns() {
        XCTAssertTrue(PatternMatcher.match("", pattern: ""))
        XCTAssertFalse(PatternMatcher.match("test", pattern: ""))
        XCTAssertFalse(PatternMatcher.match("", pattern: "test"))
    }
    
    // MARK: - Wildcard Tests
    
    func testSingleAsterisk() {
        XCTAssertTrue(PatternMatcher.match("", pattern: "*"))
        XCTAssertTrue(PatternMatcher.match("test", pattern: "*"))
        XCTAssertTrue(PatternMatcher.match("test.example.com", pattern: "*"))
        XCTAssertTrue(PatternMatcher.match("192.168.1.100", pattern: "*"))
    }
    
    func testAsteriskPrefix() {
        XCTAssertTrue(PatternMatcher.match("test.example.com", pattern: "*.example.com"))
        XCTAssertTrue(PatternMatcher.match("sub.test.example.com", pattern: "*.example.com"))
        XCTAssertFalse(PatternMatcher.match("example.com", pattern: "*.example.com"))
        XCTAssertFalse(PatternMatcher.match("test.example.net", pattern: "*.example.com"))
    }
    
    func testAsteriskSuffix() {
        XCTAssertTrue(PatternMatcher.match("test.example.com", pattern: "test.*"))
        XCTAssertTrue(PatternMatcher.match("test.", pattern: "test.*"))
        XCTAssertFalse(PatternMatcher.match("test", pattern: "test.*"))
        XCTAssertFalse(PatternMatcher.match("testing.com", pattern: "test.*"))
    }
    
    func testAsteriskMiddle() {
        XCTAssertTrue(PatternMatcher.match("test.example.com", pattern: "test.*.com"))
        XCTAssertTrue(PatternMatcher.match("test.sub.example.com", pattern: "test.*.com"))
        XCTAssertFalse(PatternMatcher.match("test.com", pattern: "test.*.com"))  // Nothing between dots
        XCTAssertFalse(PatternMatcher.match("test.example.net", pattern: "test.*.com"))
    }
    
    func testMultipleAsterisks() {
        // OpenSSH optimizes consecutive asterisks
        XCTAssertTrue(PatternMatcher.match("test", pattern: "**"))
        XCTAssertTrue(PatternMatcher.match("test", pattern: "***"))
        XCTAssertTrue(PatternMatcher.match("192.168.1.100", pattern: "192.168.*.*"))
        XCTAssertTrue(PatternMatcher.match("192.168.1.1", pattern: "192.168.*.*"))
        XCTAssertFalse(PatternMatcher.match("192.168.1", pattern: "192.168.*.*"))
    }
    
    // MARK: - Question Mark Tests
    
    func testSingleQuestionMark() {
        XCTAssertTrue(PatternMatcher.match("a", pattern: "?"))
        XCTAssertTrue(PatternMatcher.match("1", pattern: "?"))
        XCTAssertTrue(PatternMatcher.match(".", pattern: "?"))
        XCTAssertFalse(PatternMatcher.match("", pattern: "?"))
        XCTAssertFalse(PatternMatcher.match("ab", pattern: "?"))
    }
    
    func testQuestionMarkInPattern() {
        XCTAssertTrue(PatternMatcher.match("test", pattern: "te?t"))
        XCTAssertTrue(PatternMatcher.match("text", pattern: "te?t"))
        XCTAssertFalse(PatternMatcher.match("tet", pattern: "te?t"))
        XCTAssertFalse(PatternMatcher.match("teest", pattern: "te?t"))
    }
    
    func testMultipleQuestionMarks() {
        XCTAssertTrue(PatternMatcher.match("abc", pattern: "???"))
        XCTAssertTrue(PatternMatcher.match("123", pattern: "???"))
        XCTAssertFalse(PatternMatcher.match("ab", pattern: "???"))
        XCTAssertFalse(PatternMatcher.match("abcd", pattern: "???"))
    }
    
    // MARK: - Combined Wildcards Tests
    
    func testMixedWildcards() {
        XCTAssertTrue(PatternMatcher.match("test.txt", pattern: "t?st.*"))
        XCTAssertTrue(PatternMatcher.match("tast.doc", pattern: "t?st.*"))
        XCTAssertTrue(PatternMatcher.match("file123.txt", pattern: "file???.txt"))
        XCTAssertTrue(PatternMatcher.match("192.168.0.1", pattern: "192.168.?.?"))
        XCTAssertFalse(PatternMatcher.match("192.168.100.1", pattern: "192.168.?.?"))
    }
    
    // MARK: - Pattern List Tests
    
    func testSimplePatternList() {
        XCTAssertEqual(PatternMatcher.matchList("test", patternList: "test,example"), .match)
        XCTAssertEqual(PatternMatcher.matchList("example", patternList: "test,example"), .match)
        XCTAssertEqual(PatternMatcher.matchList("other", patternList: "test,example"), .noMatch)
    }
    
    func testPatternListWithWildcards() {
        let patterns = "*.example.com,*.test.net,192.168.*.*"
        XCTAssertEqual(PatternMatcher.matchList("sub.example.com", patternList: patterns), .match)
        XCTAssertEqual(PatternMatcher.matchList("host.test.net", patternList: patterns), .match)
        XCTAssertEqual(PatternMatcher.matchList("192.168.1.100", patternList: patterns), .match)
        XCTAssertEqual(PatternMatcher.matchList("other.com", patternList: patterns), .noMatch)
    }
    
    func testNegatedPatterns() {
        XCTAssertEqual(PatternMatcher.matchList("test", patternList: "!test"), .negatedMatch)
        XCTAssertEqual(PatternMatcher.matchList("example", patternList: "!test"), .noMatch)
        
        // Mixed patterns with negation
        let patterns = "*,!*.evil.com"
        XCTAssertEqual(PatternMatcher.matchList("good.com", patternList: patterns), .match)
        XCTAssertEqual(PatternMatcher.matchList("bad.evil.com", patternList: patterns), .negatedMatch)
    }
    
    func testPatternListWithSpaces() {
        let patterns = " test , example , *.domain.com "
        XCTAssertEqual(PatternMatcher.matchList("test", patternList: patterns), .match)
        XCTAssertEqual(PatternMatcher.matchList("example", patternList: patterns), .match)
        XCTAssertEqual(PatternMatcher.matchList("sub.domain.com", patternList: patterns), .match)
    }
    
    func testEmptyPatternsInList() {
        // Empty patterns should be skipped
        let patterns = "test,,example,,"
        XCTAssertEqual(PatternMatcher.matchList("test", patternList: patterns), .match)
        XCTAssertEqual(PatternMatcher.matchList("example", patternList: patterns), .match)
        XCTAssertEqual(PatternMatcher.matchList("other", patternList: patterns), .noMatch)
    }
    
    // MARK: - Hostname Tests
    
    func testHostnameMatching() {
        XCTAssertTrue(PatternMatcher.matchHostname("TEST.EXAMPLE.COM", pattern: "test.example.com"))
        XCTAssertTrue(PatternMatcher.matchHostname("test.example.com", pattern: "TEST.EXAMPLE.COM"))
        XCTAssertTrue(PatternMatcher.matchHostname("Test.Example.Com", pattern: "*.example.com"))
    }
    
    func testHostnameListMatching() {
        let patterns = "*.EXAMPLE.com,*.TEST.net"
        XCTAssertEqual(PatternMatcher.matchHostnameList("sub.example.COM", patternList: patterns), .match)
        XCTAssertEqual(PatternMatcher.matchHostnameList("HOST.test.NET", patternList: patterns), .match)
        XCTAssertEqual(PatternMatcher.matchHostnameList("other.com", patternList: patterns), .noMatch)
    }
    
    // MARK: - User Pattern Tests
    
    func testUserPatternMatching() {
        // Simple username
        XCTAssertTrue(PatternMatcher.matchUser("alice", pattern: "alice"))
        XCTAssertTrue(PatternMatcher.matchUser("alice", pattern: "ali*"))
        XCTAssertTrue(PatternMatcher.matchUser("alice", pattern: "alic?"))
        
        // Username with domain
        XCTAssertTrue(PatternMatcher.matchUser("alice@example.com", pattern: "alice@example.com"))
        XCTAssertTrue(PatternMatcher.matchUser("alice@example.com", pattern: "*@example.com"))
        XCTAssertTrue(PatternMatcher.matchUser("alice@example.com", pattern: "alice@*.com"))
        
        // Domain-only pattern
        XCTAssertTrue(PatternMatcher.matchUser("alice@example.com", pattern: "@example.com"))
        XCTAssertTrue(PatternMatcher.matchUser("bob@example.com", pattern: "@example.com"))
        XCTAssertFalse(PatternMatcher.matchUser("alice@other.com", pattern: "@example.com"))
        
        // Mixed patterns - @*.com is not a valid pattern in OpenSSH
        // The pattern should be *@*.com for users at any .com domain
        XCTAssertFalse(PatternMatcher.matchUser("alice", pattern: "@example.com"))
    }
    
    // MARK: - Address Pattern Tests
    
    func testAddressPatternMatching() {
        // IP address patterns
        XCTAssertTrue(PatternMatcher.matchAddress("192.168.1.100", pattern: "192.168.1.100"))
        XCTAssertTrue(PatternMatcher.matchAddress("192.168.1.100", pattern: "192.168.1.*"))
        XCTAssertTrue(PatternMatcher.matchAddress("192.168.1.100", pattern: "192.168.*.*"))
        
        // Hostname patterns
        XCTAssertTrue(PatternMatcher.matchAddress("test.example.com", pattern: "*.example.com"))
        XCTAssertTrue(PatternMatcher.matchAddress("test.example.com", pattern: "test.*"))
        
        // CIDR patterns (requires CIDRMatcher)
        XCTAssertTrue(PatternMatcher.matchAddress("192.168.1.100", pattern: "192.168.1.0/24"))
        XCTAssertFalse(PatternMatcher.matchAddress("192.168.2.100", pattern: "192.168.1.0/24"))
    }
    
    // MARK: - Edge Cases
    
    func testSpecialCharacters() {
        // Special characters should be treated literally
        XCTAssertTrue(PatternMatcher.match("test.file", pattern: "test.file"))
        XCTAssertFalse(PatternMatcher.match("testxfile", pattern: "test.file"))
        
        XCTAssertTrue(PatternMatcher.match("test[1]", pattern: "test[1]"))
        XCTAssertTrue(PatternMatcher.match("test$value", pattern: "test$value"))
        XCTAssertTrue(PatternMatcher.match("test^start", pattern: "test^start"))
    }
    
    func testLongPatterns() {
        let longString = String(repeating: "a", count: 1000)
        XCTAssertTrue(PatternMatcher.match(longString, pattern: "*"))
        XCTAssertTrue(PatternMatcher.match(longString, pattern: "a*"))
        XCTAssertTrue(PatternMatcher.match(longString + "b", pattern: "*b"))
    }
    
    func testComplexPatterns() {
        // Patterns that might cause backtracking issues
        XCTAssertTrue(PatternMatcher.match("aaaaaaaaab", pattern: "a*a*a*a*a*b"))
        XCTAssertFalse(PatternMatcher.match("aaaaaaaaaa", pattern: "a*a*a*a*a*b"))
        
        // Patterns with multiple wildcards
        XCTAssertTrue(PatternMatcher.match("start.middle.end", pattern: "start*middle*end"))
        XCTAssertTrue(PatternMatcher.match("start.x.y.z.middle.a.b.c.end", pattern: "start*middle*end"))
        XCTAssertFalse(PatternMatcher.match("start.middle", pattern: "start*middle*end"))
    }
    
    // MARK: - String Extension Tests
    
    func testStringExtensions() {
        XCTAssertTrue("test.example.com".matches(pattern: "*.example.com"))
        XCTAssertEqual("test".matches(patternList: "test,example"), .match)
        XCTAssertEqual("other".matches(patternList: "test,example"), .noMatch)
    }
    
    // MARK: - New Functionality Tests
    
    func testMatchHostAndIP() {
        // Test with both hostname and IP
        XCTAssertEqual(PatternMatcher.matchHostAndIP("server.example.com", ipAddress: "192.168.1.100", patternList: "*.example.com"), .match)
        XCTAssertEqual(PatternMatcher.matchHostAndIP("server.example.com", ipAddress: "192.168.1.100", patternList: "192.168.1.*"), .match)
        XCTAssertEqual(PatternMatcher.matchHostAndIP("server.example.com", ipAddress: "192.168.1.100", patternList: "*.other.com"), .noMatch)
        
        // Test with negation
        XCTAssertEqual(PatternMatcher.matchHostAndIP("bad.evil.com", ipAddress: "10.0.0.1", patternList: "*,!*.evil.com"), .negatedMatch)
        
        // Test with nil values
        XCTAssertEqual(PatternMatcher.matchHostAndIP(nil, ipAddress: "192.168.1.100", patternList: "192.168.1.*"), .match)
        XCTAssertEqual(PatternMatcher.matchHostAndIP("server.example.com", ipAddress: nil, patternList: "*.example.com"), .match)
        XCTAssertEqual(PatternMatcher.matchHostAndIP(nil, ipAddress: nil, patternList: "*"), .noMatch)
    }
    
    func testMatchLists() {
        // Algorithm negotiation tests
        XCTAssertEqual(PatternMatcher.matchLists("aes256-ctr,aes128-ctr,3des-cbc", serverList: "aes128-ctr,aes256-ctr"), "aes256-ctr")
        XCTAssertEqual(PatternMatcher.matchLists("hmac-sha2-256,hmac-sha1", serverList: "hmac-sha1,hmac-sha2-512"), "hmac-sha1")
        XCTAssertNil(PatternMatcher.matchLists("chacha20-poly1305", serverList: "aes256-ctr,aes128-ctr"))
        
        // Empty lists
        XCTAssertNil(PatternMatcher.matchLists("", serverList: "aes256-ctr"))
        XCTAssertNil(PatternMatcher.matchLists("aes256-ctr", serverList: ""))
    }
    
    func testFilterLists() {
        // Deny list filtering
        let list = "aes256-ctr,aes128-ctr,3des-cbc,arcfour"
        XCTAssertEqual(PatternMatcher.filterDenyList(list, denyList: "3des-cbc,arcfour"), "aes256-ctr,aes128-ctr")
        XCTAssertEqual(PatternMatcher.filterDenyList(list, denyList: "*-cbc"), "aes256-ctr,aes128-ctr,arcfour")
        XCTAssertEqual(PatternMatcher.filterDenyList(list, denyList: "*"), "")
        
        // Allow list filtering
        XCTAssertEqual(PatternMatcher.filterAllowList(list, allowList: "aes*"), "aes256-ctr,aes128-ctr")
        XCTAssertEqual(PatternMatcher.filterAllowList(list, allowList: "*-ctr"), "aes256-ctr,aes128-ctr")
        XCTAssertEqual(PatternMatcher.filterAllowList(list, allowList: "chacha*"), "")
    }
    
    func testPatternValidation() {
        // Pattern size validation
        XCTAssertTrue(PatternMatcher.validatePatternListSize("test,example,*.domain.com"))
        XCTAssertTrue(PatternMatcher.validatePatternListSize(String(repeating: "a", count: 1000)))
        XCTAssertFalse(PatternMatcher.validatePatternListSize(String(repeating: "a", count: 1024)))
        
        // CIDR validation
        XCTAssertTrue(PatternMatcher.validateCIDRList("192.168.1.0/24"))
        XCTAssertTrue(PatternMatcher.validateCIDRList("192.168.1.0/24,10.0.0.0/8"))
        XCTAssertTrue(PatternMatcher.validateCIDRList("2001:db8::/32"))
        XCTAssertTrue(PatternMatcher.validateCIDRList("2001:db8::/32,fd00::/8"))
        
        // Invalid CIDR
        XCTAssertFalse(PatternMatcher.validateCIDRList("192.168.1.0/33"))  // Invalid prefix
        XCTAssertFalse(PatternMatcher.validateCIDRList("192.168.1.0/24,invalid"))  // Invalid characters
        XCTAssertFalse(PatternMatcher.validateCIDRList("192.168.1.0/"))  // Missing prefix
        XCTAssertFalse(PatternMatcher.validateCIDRList("2001:db8::/129"))  // Invalid IPv6 prefix
    }
    
    func testUserGroupPatternList() {
        // Basic user matching
        XCTAssertEqual(PatternMatcher.matchUserGroupPatternList("alice", hostname: nil, ipAddress: nil, patternList: "alice,bob"), .match)
        XCTAssertEqual(PatternMatcher.matchUserGroupPatternList("charlie", hostname: nil, ipAddress: nil, patternList: "alice,bob"), .noMatch)
        
        // User@host patterns
        XCTAssertEqual(PatternMatcher.matchUserGroupPatternList("alice", hostname: "server.example.com", ipAddress: nil, patternList: "alice@*.example.com"), .match)
        XCTAssertEqual(PatternMatcher.matchUserGroupPatternList("alice", hostname: "server.other.com", ipAddress: nil, patternList: "alice@*.example.com"), .noMatch)
        XCTAssertEqual(PatternMatcher.matchUserGroupPatternList("alice", hostname: nil, ipAddress: "192.168.1.100", patternList: "alice@192.168.1.*"), .match)
        
        // Negation
        XCTAssertEqual(PatternMatcher.matchUserGroupPatternList("baduser", hostname: nil, ipAddress: nil, patternList: "*,!baduser"), .negatedMatch)
        
        // Group patterns (would need GroupMembershipChecker to test properly)
        // This test just verifies the pattern is recognized but returns noMatch without a checker
        XCTAssertEqual(PatternMatcher.matchUserGroupPatternList("alice", hostname: nil, ipAddress: nil, patternList: "%admin"), .noMatch)
    }
    
    // MARK: - Strict CIDR Matching Tests
    
    func testStrictCIDRMatching() {
        // Valid CIDR matching
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "192.168.1.0/24"), 1)
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "192.168.0.0/16"), 1)
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "10.0.0.0/8,192.168.1.0/24"), 1)
        
        // No match
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.2.100", against: "192.168.1.0/24"), 0)
        XCTAssertEqual(AddressValidator.matchCIDRList("10.0.0.1", against: "192.168.0.0/16"), 0)
        
        // Invalid formats (no wildcards allowed)
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "192.168.*.*"), -1)
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "!192.168.1.0/24"), -1) // No negation
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "192.168.1.100"), -1) // Must have /
        
        // IPv6 CIDR matching
        XCTAssertEqual(AddressValidator.matchCIDRList("2001:db8::1", against: "2001:db8::/32"), 1)
        XCTAssertEqual(AddressValidator.matchCIDRList("2001:db8::1", against: "2001:db9::/32"), 0)
        
        // Invalid CIDR format
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "192.168.1.0/33"), -1)
        XCTAssertEqual(AddressValidator.matchCIDRList("192.168.1.100", against: "invalid/24"), -1)
    }
    
    func testStrictCIDRValidation() {
        // Valid CIDR lists
        XCTAssertTrue(AddressValidator.validateCIDRList("192.168.1.0/24"))
        XCTAssertTrue(AddressValidator.validateCIDRList("192.168.1.0/24,10.0.0.0/8"))
        XCTAssertTrue(AddressValidator.validateCIDRList("2001:db8::/32"))
        XCTAssertTrue(AddressValidator.validateCIDRList("2001:db8::/32,fd00::/8"))
        
        // Invalid - contains wildcards
        XCTAssertFalse(AddressValidator.validateCIDRList("192.168.*.*"))
        
        // Invalid - contains negation
        XCTAssertFalse(AddressValidator.validateCIDRList("!192.168.1.0/24"))
        
        // Invalid - no CIDR notation
        XCTAssertFalse(AddressValidator.validateCIDRList("192.168.1.100"))
        
        // Invalid - bad characters
        XCTAssertFalse(AddressValidator.validateCIDRList("192.168.1.0/24;DROP TABLE"))
        XCTAssertFalse(AddressValidator.validateCIDRList("192.168.1.0/24 OR 1=1"))
        
        // Invalid - prefix out of range
        XCTAssertFalse(AddressValidator.validateCIDRList("192.168.1.0/33"))
        XCTAssertFalse(AddressValidator.validateCIDRList("2001:db8::/129"))
        
        // Invalid - too long
        let longIPv6 = String(repeating: "a", count: 50)
        XCTAssertFalse(AddressValidator.validateCIDRList("\(longIPv6)/128"))
    }
}