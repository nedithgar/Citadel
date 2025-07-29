import NIO
import Foundation
import BigInt

extension ByteBuffer {
    mutating func writeSFTPDate(_ date: Date) {
        writeInteger(UInt32(date.timeIntervalSince1970))
    }
    
    mutating func readSFTPDate() -> Date? {
        guard let date = readInteger(as: UInt32.self) else {
            return nil
        }
        
        return Date(timeIntervalSince1970: TimeInterval(date))
    }
    
    mutating func writeSFTPFileAttributes(_ attributes: SFTPFileAttributes) {
        writeInteger(attributes.flags.rawValue)
        
        if let size = attributes.size {
            writeInteger(size)
        }
        
        if let uidgid = attributes.uidgid {
            writeInteger(uidgid.userId)
            writeInteger(uidgid.groupId)
        }
        
        if let permissions = attributes.permissions {
            writeInteger(permissions)
        }
        
        if let accessModificationTime = attributes.accessModificationTime {
            writeSFTPDate(accessModificationTime.accessTime)
            writeSFTPDate(accessModificationTime.modificationTime)
        }
        
        for (key, value) in attributes.extended {
            writeSSHString(key)
            writeSSHString(value)
        }
    }
    
    mutating func readSFTPFileAttributes() -> SFTPFileAttributes? {
        guard let _flags = readInteger(as: UInt32.self) else {
            return nil
        }
        
        let flags = SFTPFileAttributes.Flags(rawValue: _flags)
        var attributes = SFTPFileAttributes()
        
        if flags.contains(.size) {
            guard let size = readInteger(as: UInt64.self) else {
                return nil
            }
            
            attributes.size = size
        }
        
        if flags.contains(.uidgid) {
            guard
                let uid = readInteger(as: UInt32.self),
                let gid = readInteger(as: UInt32.self)
            else {
                return nil
            }
            
            attributes.uidgid = .init(
                userId: uid,
                groupId: gid
            )
        }
        
        if flags.contains(.permissions) {
            guard let permissions = readInteger(as: UInt32.self) else {
                return nil
            }
            
            attributes.permissions = permissions
        }
        
        if flags.contains(.acmodtime) {
            guard
                let accessTime = readSFTPDate(),
                let modificationTime = readSFTPDate()
            else {
                return nil
            }
            
            attributes.accessModificationTime = .init(
                accessTime: accessTime,
                modificationTime: modificationTime
            )
        }
        
        if flags.contains(.extended) {
            guard let extendedCount = readInteger(as: UInt32.self) else {
                return nil
            }
            
            for _ in 0..<extendedCount {
                guard
                    let type = readSSHString(),
                    let data = readSSHString()
                else {
                    return nil
                }
                
                attributes.extended.append((type, data))
            }
        }
        
        return attributes
    }
    
    mutating func writeSSHString(_ buffer: inout ByteBuffer) {
        self.writeInteger(UInt32(buffer.readableBytes))
        writeBuffer(&buffer)
    }
    
    mutating func writeSSHString(_ string: String) {
        let oldWriterIndex = writerIndex
        moveWriterIndex(forwardBy: 4)
        writeString(string)
        setInteger(UInt32(writerIndex - oldWriterIndex - 4), at: oldWriterIndex)
    }
    
    @discardableResult
    mutating func writeSSHString(_ data: Data) -> Int {
        let oldWriterIndex = writerIndex
        writeInteger(UInt32(data.count))
        writeBytes(data)
        return writerIndex - oldWriterIndex
    }
    
    @discardableResult
    mutating func writeSSHString<S: Sequence>(_ bytes: S) -> Int where S.Element == UInt8 {
        let data = Data(bytes)
        return writeSSHString(data)
    }
    
    mutating func readSSHString() -> String? {
        guard
            let length = getInteger(at: self.readerIndex, as: UInt32.self),
            let string = getString(at: self.readerIndex + 4, length: Int(length))
        else {
            return nil
        }
        
        moveReaderIndex(forwardBy: 4 + Int(length))
        return string
    }
    
    mutating func readSSHBuffer() -> ByteBuffer? {
        guard
            let length = getInteger(at: self.readerIndex, as: UInt32.self),
            let slice = getSlice(at: self.readerIndex + 4, length: Int(length))
        else {
            return nil
        }
        
        moveReaderIndex(forwardBy: 4 + Int(length))
        return slice
    }
    
    mutating func readSSHBignum() -> Data? {
        // SSH bignum format: a 4-byte length field followed by the bignum data.
        // The data may have a leading zero byte if it was added during serialization
        // to ensure the number is interpreted as unsigned (preventing MSB issues).
        guard let buffer = readSSHBuffer() else {
            return nil
        }
        
        return buffer.getData(at: 0, length: buffer.readableBytes)
    }
    
    mutating func writeSSHBignum(_ bignum: BigInt) {
        var data = bignum.serialize()
        
        // SSH bignum format requires that the number is always interpreted as unsigned.
        // If the most significant bit (MSB) of the first byte is set, the number could
        // be misinterpreted as negative in two's complement representation. To prevent
        // this, a zero byte is prepended to the data, ensuring the MSB is not set.
        if !data.isEmpty && (data[0] & 0x80) != 0 {
            data.insert(0, at: 0)
        }
        
        // Write the length of the bignum data as a 4-byte unsigned integer, followed by the data itself
        writeInteger(UInt32(data.count))
        writeBytes(data)
    }
}
