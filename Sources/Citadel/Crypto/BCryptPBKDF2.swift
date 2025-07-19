import Foundation
import Crypto
import CCryptoBoringSSL

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
        let sha2pass = SHA512.hash(data: password)
        
        var key = Data(count: keyLength)
        let stride = (keyLength + BCRYPT_HASHSIZE - 1) / BCRYPT_HASHSIZE
        let amt = (keyLength + stride - 1) / stride
        
        let origKeyLen = keyLength
        
        // pbkdf2 deviation: output the key material non-linearly
        for count in 1...UInt32.max {
            if (Int(count - 1) * amt) >= origKeyLen {
                break
            }
            var countsalt = Data()
            countsalt.append(salt)
            countsalt.append(contentsOf: withUnsafeBytes(of: count.bigEndian) { Data($0) })
            
            let sha2countsalt = SHA512.hash(data: countsalt)
            
            var tmpout = try bcryptHash(
                sha2pass: Data(sha2pass),
                sha2salt: Data(sha2countsalt)
            )
            
            var out = tmpout
            
            for _ in 1..<rounds {
                let sha2tmpout = SHA512.hash(data: tmpout)
                tmpout = try bcryptHash(
                    sha2pass: Data(sha2pass),
                    sha2salt: Data(sha2tmpout)
                )
                
                for j in 0..<out.count {
                    out[j] ^= tmpout[j]
                }
            }
            
            // pbkdf2 deviation: output the key material non-linearly
            for i in 0..<amt {
                let destIdx = i * stride + Int(count - 1)
                if destIdx >= origKeyLen {
                    break
                }
                key[destIdx] = out[i]
            }
        }
        
        return key
    }
    
    private static func bcryptHash(sha2pass: Data, sha2salt: Data) throws -> Data {
        var state = BlowfishContext()
        let ciphertext: [UInt8] = Array("OxychromaticBlowfishSwatDynamite".utf8)
        var cdata = [UInt32](repeating: 0, count: BCRYPT_WORDS)
        
        state.initializeState()
        state.expandState(data: Array(sha2salt), key: Array(sha2pass))
        
        for _ in 0..<64 {
            state.expand0State(key: Array(sha2salt))
            state.expand0State(key: Array(sha2pass))
        }
        
        var j: UInt16 = 0
        for i in 0..<BCRYPT_WORDS {
            cdata[i] = BlowfishContext.stream2word(ciphertext, &j)
        }
        
        for _ in 0..<64 {
            state.encrypt(&cdata, blocks: BCRYPT_WORDS / 2)
        }
        
        var out = Data(count: BCRYPT_HASHSIZE)
        for i in 0..<BCRYPT_WORDS {
            out[4 * i + 3] = UInt8((cdata[i] >> 24) & 0xff)
            out[4 * i + 2] = UInt8((cdata[i] >> 16) & 0xff)
            out[4 * i + 1] = UInt8((cdata[i] >> 8) & 0xff)
            out[4 * i + 0] = UInt8(cdata[i] & 0xff)
        }
        
        return out
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