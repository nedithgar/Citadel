import Foundation

/// Helpers for encoding ECDSA signatures in ASN.1 DER format
enum ECDSASignatureEncoding {
    /// Encodes an ECDSA signature (r, s) as ASN.1 DER format
    /// 
    /// The ASN.1 structure is:
    /// ```
    /// ECDSASignature ::= SEQUENCE {
    ///     r INTEGER,
    ///     s INTEGER
    /// }
    /// ```
    static func encodeSignature(r: Data, s: Data) -> Data {
        let encodedR = encodeInteger(r)
        let encodedS = encodeInteger(s)
        
        // SEQUENCE tag (0x30) + length + contents
        var result = Data([0x30])
        let sequenceContent = encodedR + encodedS
        result.append(lengthField(of: sequenceContent.count))
        result.append(sequenceContent)
        
        return result
    }
    
    /// Encodes a single integer value in ASN.1 DER format
    private static func encodeInteger(_ value: Data) -> Data {
        var data = value
        
        // Remove leading zeros (except if needed to indicate positive number)
        while data.count > 1 && data[0] == 0x00 && (data[1] & 0x80) == 0 {
            data = data.dropFirst()
        }
        
        // Add leading zero if high bit is set (to ensure positive interpretation)
        if !data.isEmpty && (data[0] & 0x80) != 0 {
            data = Data([0x00]) + data
        }
        
        // INTEGER tag (0x02) + length + value
        var result = Data([0x02])
        result.append(lengthField(of: data.count))
        result.append(data)
        
        return result
    }
    
    /// Encodes the length field for ASN.1 DER
    private static func lengthField(of length: Int) -> Data {
        if length < 128 {
            return Data([UInt8(length)])
        } else if length < 256 {
            return Data([0x81, UInt8(length)])
        } else if length < 65536 {
            return Data([0x82, UInt8(length >> 8), UInt8(length & 0xFF)])
        } else {
            fatalError("Length too large for ASN.1 encoding")
        }
    }
}