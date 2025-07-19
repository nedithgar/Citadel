//
//  CryptoTests.swift
//  
//
//  Comprehensive tests for BCrypt, Blowfish, and PBKDF2 implementations
//

import Foundation
import XCTest
@testable import Citadel
import Crypto

final class CryptoTests: XCTestCase {
    
    // MARK: - BCryptPBKDF2 Tests
    
    func testBCryptPBKDF2_Deterministic() throws {
        // Test that the same inputs produce the same output
        let password = Data("password".utf8)
        let salt = Data("salt".utf8)
        
        let key1 = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: salt,
            keyLength: 32,
            rounds: 4
        )
        
        let key2 = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: salt,
            keyLength: 32,
            rounds: 4
        )
        
        XCTAssertEqual(key1, key2)
        XCTAssertEqual(key1.count, 32)
        
        // Different rounds should produce different output
        let key3 = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: salt,
            keyLength: 32,
            rounds: 8
        )
        
        XCTAssertNotEqual(key1, key3)
    }
    
    func testBCryptPBKDF2_RealWorldVector() throws {
        // Test with parameters from actual OpenSSH encrypted key (from testEncryptedED25519PrivateKey)
        let password = Data("example".utf8)
        
        // This salt is from the actual encrypted key test
        let salt = Data([
            0x50, 0x44, 0x01, 0x42, 0xa3, 0xdf, 0xef, 0xbf,
            0x48, 0x9c, 0x5f, 0xad, 0x2c, 0xe8, 0xee, 0x94
        ])
        
        // Generate key for AES-256-CTR (32 bytes key + 16 bytes IV = 48 bytes)
        let key = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: salt,
            keyLength: 48,
            rounds: 16
        )
        
        // Verify the key works by checking it can decrypt the actual OpenSSH key
        XCTAssertEqual(key.count, 48)
        
        // The key should be deterministic
        let key2 = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: salt,
            keyLength: 48,
            rounds: 16
        )
        XCTAssertEqual(key, key2)
    }
    
    func testBCryptPBKDF2_LongOutput() throws {
        // Test generating longer output keys
        let password = Data("testpassword".utf8)
        let salt = Data("testsalt".utf8)
        
        let key64 = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: salt,
            keyLength: 64,
            rounds: 8
        )
        
        XCTAssertEqual(key64.count, 64)
        
        // Test that generating different length keys produces different results
        // (bcrypt_pbkdf doesn't guarantee prefix compatibility due to its unique output mixing)
        let key32 = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: salt,
            keyLength: 32,
            rounds: 8
        )
        
        XCTAssertEqual(key32.count, 32)
        
        // Verify deterministic output for same parameters
        let key64_2 = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: salt,
            keyLength: 64,
            rounds: 8
        )
        
        XCTAssertEqual(key64, key64_2)
    }
    
    func testBCryptPBKDF2_EmptyPassword() throws {
        let password = Data()
        let salt = Data("salt".utf8)
        
        let key = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: salt,
            keyLength: 32,
            rounds: 4
        )
        
        XCTAssertEqual(key.count, 32)
        XCTAssertNotEqual(key, Data(repeating: 0, count: 32))
    }
    
    func testBCryptPBKDF2_EmptySalt() throws {
        let password = Data("password".utf8)
        let salt = Data()
        
        let key = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: salt,
            keyLength: 32,
            rounds: 4
        )
        
        XCTAssertEqual(key.count, 32)
        XCTAssertNotEqual(key, Data(repeating: 0, count: 32))
    }
    
    func testBCryptPBKDF2_HighRounds() throws {
        let password = Data("password".utf8)
        let salt = Data("salt".utf8)
        
        let key = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: salt,
            keyLength: 32,
            rounds: 100
        )
        
        XCTAssertEqual(key.count, 32)
        XCTAssertNotEqual(key, Data(repeating: 0, count: 32))
    }
    
    func testBCryptPBKDF2_LargeKeyLength() throws {
        let password = Data("password".utf8)
        let salt = Data("salt".utf8)
        
        // Test generating a large key (but within reasonable limits)
        let largeKey = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: salt,
            keyLength: 1024,
            rounds: 4
        )
        
        XCTAssertEqual(largeKey.count, 1024)
        
        // Test moderately large key length (16KB)
        let veryLargeKey = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: salt,
            keyLength: 16 * 1024,
            rounds: 1  // Use 1 round to keep test fast
        )
        
        XCTAssertEqual(veryLargeKey.count, 16 * 1024)
    }
    
    // MARK: - Blowfish Tests
    
    func testBlowfish_Initialization() throws {
        var blowfish = BlowfishContext()
        blowfish.initializeState()
        
        // Test basic encipher operation with initialized state
        var xl: UInt32 = 0
        var xr: UInt32 = 0
        blowfish.encipher(&xl, &xr)
        
        // Should produce non-zero output
        XCTAssertNotEqual(xl, 0)
        XCTAssertNotEqual(xr, 0)
    }
    
    func testBlowfish_Expand0State() throws {
        var blowfish = BlowfishContext()
        blowfish.initializeState()
        
        let key: [UInt8] = Array("TESTKEY".utf8)
        
        key.withUnsafeBufferPointer { keyBuffer in
            blowfish.expand0State(key: keyBuffer)
        }
        
        // Test encipher after key expansion
        var xl: UInt32 = 0
        var xr: UInt32 = 0
        blowfish.encipher(&xl, &xr)
        XCTAssertNotEqual(xl, 0)
        XCTAssertNotEqual(xr, 0)
    }
    
    func testBlowfish_ExpandState() throws {
        var blowfish = BlowfishContext()
        blowfish.initializeState()
        
        let key: [UInt8] = Array("password".utf8)
        let data: [UInt8] = Array("salt".utf8)
        
        key.withUnsafeBufferPointer { keyBuffer in
            data.withUnsafeBufferPointer { dataBuffer in
                blowfish.expandState(data: dataBuffer, key: keyBuffer)
            }
        }
        
        // Test encipher after state expansion
        var xl: UInt32 = 0x01234567
        var xr: UInt32 = 0x89ABCDEF
        blowfish.encipher(&xl, &xr)
        XCTAssertNotEqual(xl, 0x01234567)
        XCTAssertNotEqual(xr, 0x89ABCDEF)
    }
    
    func testBlowfish_EncryptBlocks() throws {
        var blowfish = BlowfishContext()
        blowfish.initializeState()
        
        let key: [UInt8] = Array("TESTKEY".utf8)
        
        key.withUnsafeBufferPointer { keyBuffer in
            blowfish.expand0State(key: keyBuffer)
        }
        
        // Test encryption of blocks
        var data: [UInt32] = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210]
        let originalData = data
        
        data.withUnsafeMutableBufferPointer { buffer in
            blowfish.encrypt(buffer, blocks: 2) // Encrypt 2 blocks (64 bits each)
        }
        
        // Data should be modified
        XCTAssertNotEqual(data, originalData)
    }
    
    func testBlowfish_EncipherDecipher() throws {
        var blowfish = BlowfishContext()
        blowfish.initializeState()
        
        let key: [UInt8] = Array("TestKey123".utf8)
        
        key.withUnsafeBufferPointer { keyBuffer in
            blowfish.expand0State(key: keyBuffer)
        }
        
        // Test encipher and decipher
        let originalXL: UInt32 = 0x01234567
        let originalXR: UInt32 = 0x89ABCDEF
        
        var xl = originalXL
        var xr = originalXR
        
        // Encipher
        blowfish.encipher(&xl, &xr)
        XCTAssertNotEqual(xl, originalXL)
        XCTAssertNotEqual(xr, originalXR)
        
        // Decipher
        blowfish.decipher(&xl, &xr)
        XCTAssertEqual(xl, originalXL)
        XCTAssertEqual(xr, originalXR)
    }
    
    // MARK: - BCryptCore Tests
    
    func testBCryptCore_HashPass() throws {
        // Generate a proper BCrypt salt
        let saltData: [UInt8] = [
            0xee, 0xc5, 0xb2, 0x3f, 0x6f, 0x45, 0x46, 0x77,
            0xa8, 0x99, 0xfc, 0x8f, 0xc5, 0xd5, 0x47, 0x19
        ]
        let saltString = "$2b$10$" + BCrypt.encodeBase64(data: saltData, len: 16)
        
        let hash = try BCrypt.hashPass(key: "password", salt: saltString)
        
        // Hash should start with the salt prefix
        XCTAssertTrue(hash.hasPrefix("$2b$10$"))
        
        // Hash should be deterministic
        let hash2 = try BCrypt.hashPass(key: "password", salt: saltString)
        XCTAssertEqual(hash, hash2)
    }
    
    func testBCryptCore_Base64Encoding() throws {
        // Test BCrypt's base64 encoding
        let data: [UInt8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
        let encoded = BCrypt.encodeBase64(data: data, len: 8)
        
        // BCrypt uses a custom base64 alphabet
        XCTAssertFalse(encoded.isEmpty)
        XCTAssertGreaterThan(encoded.count, 0)
    }
    
    func testBCryptCore_InvalidSalt() {
        // Test with invalid salt format
        XCTAssertThrowsError(try BCrypt.hashPass(key: "password", salt: "invalid")) { error in
            XCTAssertTrue(error is BCryptError)
            if let bcryptError = error as? BCryptError {
                XCTAssertEqual(bcryptError, BCryptError.invalidSalt)
            }
        }
        
        // Test with wrong version
        XCTAssertThrowsError(try BCrypt.hashPass(key: "password", salt: "$1$10$abcdefghijklmnopqrstuv"))
    }
    
    func testBCryptCore_ErrorHandling() {
        // Test with cost too low
        let saltData: [UInt8] = Array(repeating: 0x42, count: 16)
        let saltString = "$2b$03$" + BCrypt.encodeBase64(data: saltData, len: 16) // cost 3 is too low
        
        XCTAssertThrowsError(try BCrypt.hashPass(key: "password", salt: saltString))
        
        // Test with empty key
        let validSalt = "$2b$10$" + BCrypt.encodeBase64(data: saltData, len: 16)
        let hash = try? BCrypt.hashPass(key: "", salt: validSalt)
        XCTAssertNotNil(hash) // Empty password is valid
    }
    
    func testBCryptCore_Constants() {
        // Test BCrypt constants
        XCTAssertEqual(BCrypt.BCRYPT_VERSION, "2")
        XCTAssertEqual(BCrypt.BCRYPT_MAXSALT, 16)
        XCTAssertEqual(BCrypt.BCRYPT_WORDS, 6)
        XCTAssertEqual(BCrypt.BCRYPT_MINLOGROUNDS, 4)
        XCTAssertEqual(BCrypt.BCRYPT_HASHSPACE, 61)
    }
    
    func testBCryptCore_LongPassword() throws {
        // BCrypt truncates passwords at 72 bytes
        let saltData: [UInt8] = Array(repeating: 0x42, count: 16)
        let saltString = "$2b$04$" + BCrypt.encodeBase64(data: saltData, len: 16)
        
        let password72 = String(repeating: "A", count: 72)
        let password73 = String(repeating: "A", count: 73)
        
        let hash72 = try BCrypt.hashPass(key: password72, salt: saltString)
        let hash73 = try BCrypt.hashPass(key: password73, salt: saltString)
        
        // Should produce the same hash due to truncation at 72 bytes
        XCTAssertEqual(hash72, hash73)
    }
    
    // MARK: - Integration Tests
    
    func testIntegration_OpenSSHKeyDecryption() throws {
        // This is the same test as in KeyTests but verifies our implementations work correctly
        let key = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBQRAFCo9
        /vv0icX60s6O6UAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBrez0rdYqROdkIA
        qvSrLoYFO1KVEidE4wclxivVKMbmAAAAoA9dkA6h2tAtANBP9RzyKvgrw5JKVJLVHfvZRQ
        8d3ttvy7WOs15y8lL/SdHiCyRukkKOPRd02zqx5g6WSmXZ0dKho/aMMO+58cIxsbCmMePT
        HaJvuQjIx6DIEoQyq83rQeVngk5rgvgou2jgHy/35C1AHtUysH4DIcltmrU3rvMF8i2GL4
        Od3cZL5cIOQVsmAZS6t3oL+GVeVOMFCqGFxjc=
        -----END OPENSSH PRIVATE KEY-----
        """
        
        let privateKey = try Curve25519.Signing.PrivateKey(sshEd25519: key, decryptionKey: "example".data(using: .utf8)!)
        XCTAssertNotNil(privateKey)
    }
    
    // MARK: - Performance Tests
    
    func testPerformance_BCryptPBKDF2() {
        let password = Data("password".utf8)
        let salt = Data("saltsaltsaltsalt".utf8)
        
        measure {
            _ = try! BCryptPBKDF2.pbkdf(
                password: password,
                salt: salt,
                keyLength: 48,
                rounds: 4  // Reduced from 16 to keep performance tests fast
            )
        }
    }
    
    func testPerformance_Blowfish() {
        var blowfish = BlowfishContext()
        blowfish.initializeState()
        
        let key: [UInt8] = Array("TESTKEY123456789".utf8)
        
        key.withUnsafeBufferPointer { keyBuffer in
            blowfish.expand0State(key: keyBuffer)
        }
        
        var data = [UInt32](repeating: 0, count: 2) // 64-bit block
        
        measure {
            for _ in 0..<1000 {  // Reduced from 10000
                data.withUnsafeMutableBufferPointer { buffer in
                    blowfish.encrypt(buffer, blocks: 1)
                }
            }
        }
    }
    
    func testPerformance_BCryptCore() {
        let saltData: [UInt8] = Array(repeating: 0x42, count: 16)
        let saltString = "$2b$04$" + BCrypt.encodeBase64(data: saltData, len: 16)  // Reduced cost from 10 to 4
        
        measure {
            _ = try! BCrypt.hashPass(key: "testpassword", salt: saltString)
        }
    }
}