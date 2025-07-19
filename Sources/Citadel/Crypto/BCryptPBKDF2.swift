import Foundation
import Crypto

public struct BCryptPBKDF2 {
    private static let BCRYPT_WORDS: Int = 8
    private static let BCRYPT_HASHSIZE: Int = BCRYPT_WORDS * 4
    
    public static func pbkdf(
        password: Data,
        salt: Data,
        keyLength: Int,
        rounds: Int
    ) throws -> Data {
        precondition(rounds > 0, "Rounds must be positive")
        precondition(keyLength > 0, "Key length must be positive")
        
        return password.withUnsafeBytes { passwordBytes in
            salt.withUnsafeBytes { saltBytes in
                // Use ContiguousArray for better performance
                var key = ContiguousArray<UInt8>(repeating: 0, count: keyLength)
                
                pbkdfOptimized(
                    password: passwordBytes.bindMemory(to: UInt8.self),
                    salt: saltBytes.bindMemory(to: UInt8.self),
                    keyOutput: &key,
                    keyLength: keyLength,
                    rounds: rounds
                )
                
                return Data(key)
            }
        }
    }
    
    @inline(__always)
    private static func pbkdfOptimized(
        password: UnsafeBufferPointer<UInt8>,
        salt: UnsafeBufferPointer<UInt8>,
        keyOutput: inout ContiguousArray<UInt8>,
        keyLength: Int,
        rounds: Int
    ) {
        // Pre-allocate SHA512 buffers
        var sha2pass = ContiguousArray<UInt8>(repeating: 0, count: 64)
        // var sha2salt = ContiguousArray<UInt8>(repeating: 0, count: 64) // Not used
        var sha2countsalt = ContiguousArray<UInt8>(repeating: 0, count: 64)
        var sha2tmpout = ContiguousArray<UInt8>(repeating: 0, count: 64)
        
        // Hash password once
        let hashedPassword = SHA512.hash(data: password)
        sha2pass = ContiguousArray(hashedPassword)
        
        let stride = (keyLength + BCRYPT_HASHSIZE - 1) / BCRYPT_HASHSIZE
        let amt = (keyLength + stride - 1) / stride
        
        // Pre-allocate buffers for bcrypt operations
        var tmpout = ContiguousArray<UInt8>(repeating: 0, count: BCRYPT_HASHSIZE)
        var out = ContiguousArray<UInt8>(repeating: 0, count: BCRYPT_HASHSIZE)
        
        // pbkdf2 deviation: output the key material non-linearly
        for count: UInt32 in 1...UInt32.max {
            if (Int(count - 1) * amt) >= keyLength {
                break
            }
            
            // Create countsalt = salt || count (big-endian)
            var countsalt = ContiguousArray<UInt8>()
            countsalt.reserveCapacity(salt.count + 4)
            countsalt.append(contentsOf: salt)
            let countBE = count.bigEndian
            withUnsafeBytes(of: countBE) { bytes in
                countsalt.append(contentsOf: bytes)
            }
            
            // Hash countsalt
            let hashedCountsalt = SHA512.hash(data: countsalt)
            sha2countsalt = ContiguousArray(hashedCountsalt)
            
            // First round
            sha2pass.withUnsafeBufferPointer { sha2passBuffer in
                sha2countsalt.withUnsafeBufferPointer { sha2countsaltBuffer in
                    tmpout.withUnsafeMutableBufferPointer { tmpoutBuffer in
                        bcryptHashOptimized(
                            sha2pass: sha2passBuffer,
                            sha2salt: sha2countsaltBuffer,
                            output: tmpoutBuffer
                        )
                    }
                }
            }
            
            // Copy first round to out
            out = tmpout
            
            // Subsequent rounds
            for _ in 1..<rounds {
                // Hash tmpout
                let hashedTmpout = SHA512.hash(data: tmpout)
                sha2tmpout = ContiguousArray(hashedTmpout)
                
                // bcrypt hash
                sha2pass.withUnsafeBufferPointer { sha2passBuffer in
                    sha2tmpout.withUnsafeBufferPointer { sha2tmpoutBuffer in
                        tmpout.withUnsafeMutableBufferPointer { tmpoutBuffer in
                            bcryptHashOptimized(
                                sha2pass: sha2passBuffer,
                                sha2salt: sha2tmpoutBuffer,
                                output: tmpoutBuffer
                            )
                        }
                    }
                }
                
                // XOR with out
                for j in 0..<BCRYPT_HASHSIZE {
                    out[j] ^= tmpout[j]
                }
            }
            
            // pbkdf2 deviation: output the key material non-linearly
            for i in 0..<amt {
                let destIdx = i * stride + Int(count - 1)
                if destIdx >= keyLength {
                    break
                }
                keyOutput[destIdx] = out[i]
            }
        }
    }
    
    @inline(__always)
    private static func bcryptHashOptimized(
        sha2pass: UnsafeBufferPointer<UInt8>,
        sha2salt: UnsafeBufferPointer<UInt8>,
        output: UnsafeMutableBufferPointer<UInt8>
    ) {
        var state = BlowfishContext()
        let ciphertext = ContiguousArray("OxychromaticBlowfishSwatDynamite".utf8)
        var cdata = ContiguousArray<UInt32>(repeating: 0, count: BCRYPT_WORDS)
        
        state.initializeState()
        state.expandState(data: sha2salt, key: sha2pass)
        
        for _ in 0..<64 {
            state.expand0State(key: sha2salt)
            state.expand0State(key: sha2pass)
        }
        
        // Convert ciphertext to UInt32 array
        ciphertext.withUnsafeBufferPointer { ciphertextBuffer in
            var j = 0
            for i in 0..<BCRYPT_WORDS {
                cdata[i] = BlowfishContext.stream2word(ciphertextBuffer, &j)
            }
        }
        
        // Encrypt
        cdata.withUnsafeMutableBufferPointer { cdataBuffer in
            for _ in 0..<64 {
                state.encrypt(cdataBuffer, blocks: BCRYPT_WORDS / 2)
            }
        }
        
        // Convert back to bytes (big-endian)
        for i in 0..<BCRYPT_WORDS {
            output[4 * i + 3] = UInt8((cdata[i] >> 24) & 0xff)
            output[4 * i + 2] = UInt8((cdata[i] >> 16) & 0xff)
            output[4 * i + 1] = UInt8((cdata[i] >> 8) & 0xff)
            output[4 * i + 0] = UInt8(cdata[i] & 0xff)
        }
    }
}

public func citadel_bcrypt_pbkdf(
    _ pass: UnsafePointer<UInt8>,
    _ passlen: Int,
    _ salt: UnsafePointer<UInt8>,
    _ saltlen: Int,
    _ key: UnsafeMutablePointer<UInt8>,
    _ keylen: Int,
    _ rounds: UInt32
) -> Int32 {
    let password = Data(bytes: pass, count: passlen)
    let saltData = Data(bytes: salt, count: saltlen)
    
    do {
        let result = try BCryptPBKDF2.pbkdf(
            password: password,
            salt: saltData,
            keyLength: keylen,
            rounds: Int(rounds)
        )
        result.copyBytes(to: key, count: keylen)
        return 0
    } catch {
        return -1
    }
}