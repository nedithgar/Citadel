import Foundation

enum BCryptError: Error {
    case invalidSalt
    case invalidInput
    case cryptoError
}

struct BCrypt {
    static let BCRYPT_VERSION: Character = "2"
    static let BCRYPT_MAXSALT: Int = 16
    static let BCRYPT_WORDS: Int = 6
    static let BCRYPT_MINLOGROUNDS: Int = 4
    static let BCRYPT_HASHSPACE: Int = 61
    static let BCRYPT_SALTSPACE: Int = 7 + (BCRYPT_MAXSALT * 4 + 2) / 3 + 1
    
    private static let base64Code: [UInt8] = Array("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".utf8)
    
    private static let index64: [UInt8] = {
        var result = [UInt8](repeating: 255, count: 128)
        let chars = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        for (index, char) in chars.enumerated() {
            if let ascii = char.asciiValue, ascii < 128 {
                result[Int(ascii)] = UInt8(index)
            }
        }
        return result
    }()
    
    static func hashPass(key: String, salt: String) throws -> String {
        guard let keyData = key.data(using: .utf8) else {
            throw BCryptError.invalidInput
        }
        
        var encrypted = [CChar](repeating: 0, count: BCRYPT_HASHSPACE)
        
        let result = try hashPassInternal(
            key: keyData,
            salt: salt,
            encrypted: &encrypted
        )
        
        if result < 0 {
            throw BCryptError.cryptoError
        }
        
        return String(cString: encrypted)
    }
    
    private static func hashPassInternal(key: Data, salt: String, encrypted: inout [CChar]) throws -> Int {
        var state = BlowfishContext()
        var rounds: UInt32 = 0
        var keyLen: Int
        var saltLen: UInt8
        var logr: UInt8
        var minor: UInt8
        var ciphertext: [UInt8] = Array("OrpheanBeholderScryDoubt".utf8)
        var csalt = [UInt8](repeating: 0, count: BCRYPT_MAXSALT)
        var cdata = [UInt32](repeating: 0, count: BCRYPT_WORDS)
        
        if encrypted.count < BCRYPT_HASHSPACE {
            throw BCryptError.invalidInput
        }
        
        var saltChars = Array(salt)
        var saltIndex = 0
        
        if saltChars[saltIndex] != "$" {
            throw BCryptError.invalidSalt
        }
        saltIndex += 1
        
        if saltChars[saltIndex] != BCRYPT_VERSION {
            throw BCryptError.invalidSalt
        }
        
        minor = UInt8(saltChars[saltIndex + 1].asciiValue ?? 0)
        switch minor {
        case UInt8(ascii: "a"):
            keyLen = key.count + 1
        case UInt8(ascii: "b"):
            keyLen = min(key.count, 72) + 1
        default:
            throw BCryptError.invalidSalt
        }
        
        if saltChars[saltIndex + 2] != "$" {
            throw BCryptError.invalidSalt
        }
        saltIndex += 3
        
        guard saltIndex + 2 < saltChars.count,
              let digit1 = saltChars[saltIndex].wholeNumberValue,
              let digit2 = saltChars[saltIndex + 1].wholeNumberValue else {
            throw BCryptError.invalidSalt
        }
        
        if saltIndex + 2 < saltChars.count && saltChars[saltIndex + 2] != "$" {
            throw BCryptError.invalidSalt
        }
        
        logr = UInt8(digit1 * 10 + digit2)
        if logr < BCRYPT_MINLOGROUNDS || logr > 31 {
            throw BCryptError.invalidSalt
        }
        rounds = 1 << logr
        
        saltIndex += 3
        
        let saltString = String(saltChars[saltIndex...])
        if saltString.count * 3 / 4 < BCRYPT_MAXSALT {
            throw BCryptError.invalidSalt
        }
        
        if decodeBase64(buffer: &csalt, len: BCRYPT_MAXSALT, b64data: saltString) < 0 {
            throw BCryptError.invalidSalt
        }
        saltLen = UInt8(BCRYPT_MAXSALT)
        
        var keyBytes = [UInt8](key.prefix(keyLen))
        if keyBytes.count < keyLen {
            keyBytes.append(0)
        }
        
        state.initializeState()
        state.expandState(data: csalt, key: keyBytes)
        
        for _ in 0..<rounds {
            state.expand0State(key: keyBytes)
            state.expand0State(key: csalt)
        }
        
        var j: UInt16 = 0
        for i in 0..<BCRYPT_WORDS {
            cdata[i] = BlowfishContext.stream2word(ciphertext, &j)
        }
        
        for _ in 0..<64 {
            state.encrypt(&cdata, blocks: BCRYPT_WORDS / 2)
        }
        
        for i in 0..<BCRYPT_WORDS {
            var value = cdata[i]
            ciphertext[4 * i + 3] = UInt8(value & 0xff)
            value >>= 8
            ciphertext[4 * i + 2] = UInt8(value & 0xff)
            value >>= 8
            ciphertext[4 * i + 1] = UInt8(value & 0xff)
            value >>= 8
            ciphertext[4 * i] = UInt8(value & 0xff)
        }
        
        let prefix = String(format: "$2%c$%02u$", minor, logr)
        var result = prefix
        result += encodeBase64(data: csalt, len: BCRYPT_MAXSALT)
        result += encodeBase64(data: ciphertext, len: 4 * BCRYPT_WORDS - 1)
        
        let resultBytes = Array(result.utf8)
        encrypted = resultBytes.map { CChar(bitPattern: $0) } + [0]
        
        ciphertext = [UInt8](repeating: 0, count: ciphertext.count)
        csalt = [UInt8](repeating: 0, count: csalt.count)
        cdata = [UInt32](repeating: 0, count: cdata.count)
        
        return 0
    }
    
    private static func decodeBase64(buffer: inout [UInt8], len: Int, b64data: String) -> Int {
        var bp = 0
        let chars = Array(b64data.utf8)
        var p = 0
        
        while bp < len && p < chars.count {
            let c1Char = chars[p]
            if c1Char > 127 { return -1 }
            let c1 = index64[Int(c1Char)]
            if c1 == 255 { return -1 }
            
            guard p + 1 < chars.count else { return -1 }
            let c2Char = chars[p + 1]
            if c2Char > 127 { return -1 }
            let c2 = index64[Int(c2Char)]
            if c2 == 255 { return -1 }
            
            buffer[bp] = (c1 << 2) | ((c2 & 0x30) >> 4)
            bp += 1
            if bp >= len { break }
            
            guard p + 2 < chars.count else { return -1 }
            let c3Char = chars[p + 2]
            if c3Char > 127 { return -1 }
            let c3 = index64[Int(c3Char)]
            if c3 == 255 { return -1 }
            
            buffer[bp] = ((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2)
            bp += 1
            if bp >= len { break }
            
            guard p + 3 < chars.count else { return -1 }
            let c4Char = chars[p + 3]
            if c4Char > 127 { return -1 }
            let c4 = index64[Int(c4Char)]
            if c4 == 255 { return -1 }
            
            buffer[bp] = ((c3 & 0x03) << 6) | c4
            bp += 1
            
            p += 4
        }
        
        return 0
    }
    
    static func encodeBase64(data: [UInt8], len: Int) -> String {
        var result = ""
        var p = 0
        
        while p < len {
            let c1 = data[p]
            result.append(Character(UnicodeScalar(base64Code[Int(c1 >> 2)])))
            var c1Remainder = (c1 & 0x03) << 4
            
            p += 1
            if p >= len {
                result.append(Character(UnicodeScalar(base64Code[Int(c1Remainder)])))
                break
            }
            
            let c2 = data[p]
            c1Remainder |= (c2 >> 4) & 0x0f
            result.append(Character(UnicodeScalar(base64Code[Int(c1Remainder)])))
            var c2Remainder = (c2 & 0x0f) << 2
            
            p += 1
            if p >= len {
                result.append(Character(UnicodeScalar(base64Code[Int(c2Remainder)])))
                break
            }
            
            let c3 = data[p]
            c2Remainder |= (c3 >> 6) & 0x03
            result.append(Character(UnicodeScalar(base64Code[Int(c2Remainder)])))
            result.append(Character(UnicodeScalar(base64Code[Int(c3 & 0x3f)])))
            
            p += 1
        }
        
        return result
    }
}

private extension Character {
    init(ascii: String) {
        self = Character(ascii)
    }
}

private extension UInt8 {
    init(ascii: String) {
        self = UInt8(Character(ascii).asciiValue ?? 0)
    }
}