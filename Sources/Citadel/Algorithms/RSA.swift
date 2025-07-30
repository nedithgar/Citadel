import NIO
import NIOFoundationCompat
import BigInt
import NIOSSH
import CCryptoBoringSSL
import Foundation
import Crypto

extension Insecure {
    public enum RSA {
        /// Supported RSA signature hash algorithms
        public enum SignatureHashAlgorithm: String {
            case sha1 = "ssh-rsa"
            case sha256 = "rsa-sha2-256"
            case sha512 = "rsa-sha2-512"
            
            // Certificate variants
            case sha1Cert = "ssh-rsa-cert-v01@openssh.com"
            case sha256Cert = "rsa-sha2-256-cert-v01@openssh.com"
            case sha512Cert = "rsa-sha2-512-cert-v01@openssh.com"
            
            /// Get the corresponding NID for BoringSSL
            public var nid: Int32 {
                switch self {
                case .sha1, .sha1Cert:
                    return NID_sha1
                case .sha256, .sha256Cert:
                    return NID_sha256
                case .sha512, .sha512Cert:
                    return NID_sha512
                }
            }
            
            /// Whether this algorithm represents a certificate
            public var isCertificate: Bool {
                switch self {
                case .sha1Cert, .sha256Cert, .sha512Cert:
                    return true
                default:
                    return false
                }
            }
            
            /// Get the base signature algorithm (non-certificate version)
            public var baseAlgorithm: SignatureHashAlgorithm {
                switch self {
                case .sha1Cert:
                    return .sha1
                case .sha256Cert:
                    return .sha256
                case .sha512Cert:
                    return .sha512
                default:
                    return self
                }
            }
        }
    }
}

extension Insecure.RSA {
    public class PublicKey: NIOSSHPublicKeyProtocol {
        public class var publicKeyPrefix: String { "ssh-rsa" }
        public static let keyExchangeAlgorithms = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"]
        
        // PublicExponent e
        internal let publicExponent: UnsafeMutablePointer<BIGNUM>
        
        // Modulus n
        internal let modulus: UnsafeMutablePointer<BIGNUM>
        
        deinit {
            CCryptoBoringSSL_BN_free(modulus)
            CCryptoBoringSSL_BN_free(publicExponent)
        }
        
        public var rawRepresentation: Data {
            var buffer = ByteBuffer()
            buffer.writeMPBignum(publicExponent)
            buffer.writeMPBignum(modulus)
            return buffer.readData(length: buffer.readableBytes)!
        }
        
        enum PubkeyParseError: Error {
            case invalidInitialSequence, invalidAlgorithmIdentifier, invalidSubjectPubkey, forbiddenTrailingData, invalidRSAPubkey
        }
        
        public required init(publicExponent: UnsafeMutablePointer<BIGNUM>, modulus: UnsafeMutablePointer<BIGNUM>) {
            self.publicExponent = publicExponent
            self.modulus = modulus
        }
        
        public func encrypt<D: DataProtocol>(for message: D) throws -> EncryptedMessage {
//            let message = BigUInt(Data(message))
//
//            guard message > .zero && message <= modulus - 1 else {
//                throw RSAError.messageRepresentativeOutOfRange
//            }
//
//            let result = message.power(publicExponent, modulus: modulus)
//            return EncryptedMessage(rawRepresentation: result.serialize())
            throw CitadelError.unsupported
        }
        
        public func isValidSignature<D: DataProtocol>(_ signature: Signature, for digest: D) -> Bool {
            let context = CCryptoBoringSSL_RSA_new()
            defer { CCryptoBoringSSL_RSA_free(context) }

            // Copy, so that our local `self.modulus` isn't freed by RSA_free
            let modulus = CCryptoBoringSSL_BN_new()!
            let publicExponent = CCryptoBoringSSL_BN_new()!
            
            CCryptoBoringSSL_BN_copy(modulus, self.modulus)
            CCryptoBoringSSL_BN_copy(publicExponent, self.publicExponent)
            guard CCryptoBoringSSL_RSA_set0_key(
                context,
                modulus,
                publicExponent,
                nil
            ) == 1 else {
                return false
            }
            
            // Hash the message based on the signature algorithm
            let messageData = Array(digest)
            let hashedMessage: [UInt8]
            let hashLength: Int
            
            switch signature.algorithm {
            case .sha1, .sha1Cert:
                var hash = [UInt8](repeating: 0, count: 20)
                CCryptoBoringSSL_SHA1(messageData, messageData.count, &hash)
                hashedMessage = hash
                hashLength = 20
            case .sha256, .sha256Cert:
                let hash = SHA256.hash(data: digest)
                hashedMessage = Array(hash)
                hashLength = 32
            case .sha512, .sha512Cert:
                let hash = SHA512.hash(data: digest)
                hashedMessage = Array(hash)
                hashLength = 64
            }
            
            let signatureBytes = Array(signature.rawRepresentation)
            return CCryptoBoringSSL_RSA_verify(
                signature.algorithm.nid,
                hashedMessage,
                hashLength,
                signatureBytes,
                signatureBytes.count,
                context
            ) == 1
        }
        
        public func isValidSignature<D>(_ signature: NIOSSHSignatureProtocol, for data: D) -> Bool where D : DataProtocol {
            guard let signature = signature as? Signature else {
                return false
            }
            
            return isValidSignature(signature, for: data)
        }
        
        public func write(to buffer: inout ByteBuffer) -> Int {
            // For ssh-rsa, the format is public exponent `e` followed by modulus `n`
            var writtenBytes = 0
            writtenBytes += buffer.writeMPBignum(publicExponent)
            writtenBytes += buffer.writeMPBignum(modulus)
            return writtenBytes
        }
        
        static func read(consuming buffer: inout ByteBuffer) throws -> Self {
            try read(from: &buffer)
        }
        
        public static func read(from buffer: inout ByteBuffer) throws -> Self {
            guard
                var publicExponent = buffer.readSSHBuffer(),
                var modulus = buffer.readSSHBuffer()
            else {
                throw RSAError(message: "Invalid signature format")
            }
            
            let publicExponentBytes = publicExponent.readBytes(length: publicExponent.readableBytes)!
            let modulusBytes = modulus.readBytes(length: modulus.readableBytes)!
            return self.init(
                publicExponent: CCryptoBoringSSL_BN_bin2bn(publicExponentBytes, publicExponentBytes.count, nil),
                modulus: CCryptoBoringSSL_BN_bin2bn(modulusBytes, modulusBytes.count, nil)
            )
        }
    }
    
    public struct EncryptedMessage: ContiguousBytes {
        public let rawRepresentation: Data
        
        public init<D>(rawRepresentation: D) where D : DataProtocol {
            self.rawRepresentation = Data(rawRepresentation)
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try rawRepresentation.withUnsafeBytes(body)
        }
    }
    
    public struct Signature: ContiguousBytes, NIOSSHSignatureProtocol {
        public static let signaturePrefix = "ssh-rsa"
        
        public let rawRepresentation: Data
        public let algorithm: SignatureHashAlgorithm
        
        public init<D>(rawRepresentation: D, algorithm: SignatureHashAlgorithm = .sha1) where D : DataProtocol {
            self.rawRepresentation = Data(rawRepresentation)
            self.algorithm = algorithm
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try rawRepresentation.withUnsafeBytes(body)
        }
        
        public func write(to buffer: inout ByteBuffer) -> Int {
            var writtenBytes = 0
            // Write the algorithm identifier first
            writtenBytes += buffer.writeSSHString(algorithm.rawValue.utf8)
            // Then write the signature bytes
            writtenBytes += buffer.writeSSHString(rawRepresentation)
            return writtenBytes
        }
        
        public static func read(from buffer: inout ByteBuffer) throws -> Signature {
            // Read the algorithm identifier
            guard let algorithmString = buffer.readSSHString() else {
                throw RSAError(message: "Missing signature algorithm identifier")
            }
            
            guard let algorithm = SignatureHashAlgorithm(rawValue: algorithmString) else {
                throw RSAError(message: "Unsupported signature algorithm: \(algorithmString)")
            }
            
            // Read the signature data
            guard let signatureData = buffer.readSSHBuffer() else {
                throw RSAError(message: "Invalid signature format")
            }
            
            return Signature(
                rawRepresentation: signatureData.getData(at: 0, length: signatureData.readableBytes)!,
                algorithm: algorithm
            )
        }
    }
    
    public final class PrivateKey: NIOSSHPrivateKeyProtocol {
        public static let keyPrefix = "ssh-rsa"
        
        // Private Exponent d
        internal let privateExponent: UnsafeMutablePointer<BIGNUM>
        
        // Prime factors p and q
        internal let p: UnsafeMutablePointer<BIGNUM>?
        internal let q: UnsafeMutablePointer<BIGNUM>?
        
        // iqmp = q^-1 mod p
        internal let iqmp: UnsafeMutablePointer<BIGNUM>?
        
        // Public key components
        internal let _publicKey: PublicKey
        
        public var publicKey: NIOSSHPublicKeyProtocol {
            _publicKey
        }
        
        public init(privateExponent: UnsafeMutablePointer<BIGNUM>, publicExponent: UnsafeMutablePointer<BIGNUM>, modulus: UnsafeMutablePointer<BIGNUM>, p: UnsafeMutablePointer<BIGNUM>? = nil, q: UnsafeMutablePointer<BIGNUM>? = nil, iqmp: UnsafeMutablePointer<BIGNUM>? = nil) {
            self.privateExponent = privateExponent
            self.p = p
            self.q = q
            self.iqmp = iqmp
            self._publicKey = PublicKey(publicExponent: publicExponent, modulus: modulus)
        }
        
        deinit {
            CCryptoBoringSSL_BN_free(privateExponent)
            if let p = p { CCryptoBoringSSL_BN_free(p) }
            if let q = q { CCryptoBoringSSL_BN_free(q) }
            if let iqmp = iqmp { CCryptoBoringSSL_BN_free(iqmp) }
        }
        
        public init(bits: Int = 2048, publicExponent e: BigUInt = 65537) {
            // Generate prime numbers p and q
            let p = CCryptoBoringSSL_BN_new()!
            let q = CCryptoBoringSSL_BN_new()!
            let n = CCryptoBoringSSL_BN_new()!
            let d = CCryptoBoringSSL_BN_new()!
            let phi = CCryptoBoringSSL_BN_new()!
            let p1 = CCryptoBoringSSL_BN_new()!
            let q1 = CCryptoBoringSSL_BN_new()!
            let iqmp = CCryptoBoringSSL_BN_new()!
            let ctx = CCryptoBoringSSL_BN_CTX_new()!
            
            defer {
                CCryptoBoringSSL_BN_free(phi)
                CCryptoBoringSSL_BN_free(p1)
                CCryptoBoringSSL_BN_free(q1)
                CCryptoBoringSSL_BN_CTX_free(ctx)
            }
            
            // Convert public exponent to BIGNUM
            let eBytes = Array(e.serialize())
            let eBN = CCryptoBoringSSL_BN_bin2bn(eBytes, eBytes.count, nil)!
            
            // Generate two prime numbers of half the key size
            let primeSize = bits / 2
            guard CCryptoBoringSSL_BN_generate_prime_ex(p, Int32(primeSize), 0, nil, nil, nil) == 1,
                  CCryptoBoringSSL_BN_generate_prime_ex(q, Int32(primeSize), 0, nil, nil, nil) == 1 else {
                fatalError("Failed to generate prime numbers")
            }
            
            // Calculate n = p * q
            guard CCryptoBoringSSL_BN_mul(n, p, q, ctx) == 1 else {
                fatalError("Failed to calculate modulus")
            }
            
            // Calculate phi(n) = (p-1) * (q-1)
            guard CCryptoBoringSSL_BN_sub(p1, p, CCryptoBoringSSL_BN_value_one()) == 1,
                  CCryptoBoringSSL_BN_sub(q1, q, CCryptoBoringSSL_BN_value_one()) == 1,
                  CCryptoBoringSSL_BN_mul(phi, p1, q1, ctx) == 1 else {
                fatalError("Failed to calculate phi")
            }
            
            // Calculate d = e^-1 mod phi(n)
            guard CCryptoBoringSSL_BN_mod_inverse(d, eBN, phi, ctx) != nil else {
                fatalError("Failed to calculate private exponent")
            }
            
            // Calculate iqmp = q^-1 mod p
            guard CCryptoBoringSSL_BN_mod_inverse(iqmp, q, p, ctx) != nil else {
                fatalError("Failed to calculate iqmp")
            }
            
            self.privateExponent = d
            self.p = p
            self.q = q
            self.iqmp = iqmp
            self._publicKey = .init(
                publicExponent: eBN,
                modulus: n
            )
        }
        
        /// Calculates CRT parameters dmp1 and dmq1 from d, p, q
        /// - Returns: Tuple of (dmp1, dmq1) where dmp1 = d mod (p-1) and dmq1 = d mod (q-1)
        func calculateCRTParams() -> (dmp1: UnsafeMutablePointer<BIGNUM>?, dmq1: UnsafeMutablePointer<BIGNUM>?) {
            guard let p = p, let q = q else { return (nil, nil) }
            
            let ctx = CCryptoBoringSSL_BN_CTX_new()!
            defer { CCryptoBoringSSL_BN_CTX_free(ctx) }
            
            let p1 = CCryptoBoringSSL_BN_new()!
            let q1 = CCryptoBoringSSL_BN_new()!
            let dmp1 = CCryptoBoringSSL_BN_new()!
            let dmq1 = CCryptoBoringSSL_BN_new()!
            
            defer {
                CCryptoBoringSSL_BN_free(p1)
                CCryptoBoringSSL_BN_free(q1)
            }
            
            // Calculate p-1 and q-1
            if CCryptoBoringSSL_BN_sub(p1, p, CCryptoBoringSSL_BN_value_one()) != 1 ||
               CCryptoBoringSSL_BN_sub(q1, q, CCryptoBoringSSL_BN_value_one()) != 1 {
                CCryptoBoringSSL_BN_free(dmp1)
                CCryptoBoringSSL_BN_free(dmq1)
                return (nil, nil)
            }
            
            // Calculate dmp1 = d mod (p-1) and dmq1 = d mod (q-1)
            if CCryptoBoringSSL_BN_nnmod(dmp1, privateExponent, p1, ctx) != 1 ||
               CCryptoBoringSSL_BN_nnmod(dmq1, privateExponent, q1, ctx) != 1 {
                CCryptoBoringSSL_BN_free(dmp1)
                CCryptoBoringSSL_BN_free(dmq1)
                return (nil, nil)
            }
            
            return (dmp1, dmq1)
        }
        
        public func signature<D: DataProtocol>(for message: D, algorithm: SignatureHashAlgorithm = .sha1) throws -> Signature {
            let context = CCryptoBoringSSL_RSA_new()
            defer { CCryptoBoringSSL_RSA_free(context) }

            // Copy, so that our local `self.modulus` isn't freed by RSA_free
            let modulus = CCryptoBoringSSL_BN_new()!
            let publicExponent = CCryptoBoringSSL_BN_new()!
            let privateExponent = CCryptoBoringSSL_BN_new()!
            
            CCryptoBoringSSL_BN_copy(modulus, self._publicKey.modulus)
            CCryptoBoringSSL_BN_copy(publicExponent, self._publicKey.publicExponent)
            CCryptoBoringSSL_BN_copy(privateExponent, self.privateExponent)
            guard CCryptoBoringSSL_RSA_set0_key(
                context,
                modulus,
                publicExponent,
                privateExponent
            ) == 1 else {
                throw CitadelError.signingError
            }
            
            // Set factors and CRT params if available for performance
            if let p = p, let q = q {
                let pCopy = CCryptoBoringSSL_BN_new()!
                let qCopy = CCryptoBoringSSL_BN_new()!
                CCryptoBoringSSL_BN_copy(pCopy, p)
                CCryptoBoringSSL_BN_copy(qCopy, q)
                CCryptoBoringSSL_RSA_set0_factors(context, pCopy, qCopy)
                
                if let iqmp = iqmp {
                    let (dmp1, dmq1) = calculateCRTParams()
                    if let dmp1 = dmp1, let dmq1 = dmq1 {
                        let iqmpCopy = CCryptoBoringSSL_BN_new()!
                        CCryptoBoringSSL_BN_copy(iqmpCopy, iqmp)
                        CCryptoBoringSSL_RSA_set0_crt_params(context, dmp1, dmq1, iqmpCopy)
                    }
                }
            }
            
            // Hash the message based on the selected algorithm
            let hashedMessage: [UInt8]
            switch algorithm {
            case .sha1, .sha1Cert:
                hashedMessage = Array(Insecure.SHA1.hash(data: message))
            case .sha256, .sha256Cert:
                hashedMessage = Array(SHA256.hash(data: message))
            case .sha512, .sha512Cert:
                hashedMessage = Array(SHA512.hash(data: message))
            }
            
            let out = UnsafeMutablePointer<UInt8>.allocate(capacity: 4096)
            defer { out.deallocate() }
            var outLength: UInt32 = 4096
            let result = CCryptoBoringSSL_RSA_sign(
                algorithm.nid,
                hashedMessage,
                Int(hashedMessage.count),
                out,
                &outLength,
                context
            )
            
            guard result == 1 else {
                throw CitadelError.signingError
            }
            
            return Signature(rawRepresentation: Data(bytes: out, count: Int(outLength)), algorithm: algorithm)
        }
        
        public func signature<D>(for data: D) throws -> NIOSSHSignatureProtocol where D : DataProtocol {
            return try self.signature(for: data) as Signature
        }
        
        public func decrypt(_ message: EncryptedMessage) throws -> Data {
//            let signature = BigUInt(message.rawRepresentation)
//
//            switch storage {
//            case let .privateExponent(privateExponent, modulus):
//                guard signature >= .zero && signature <= privateExponent else {
//                    throw RSAError.ciphertextRepresentativeOutOfRange
//                }
//
//                return signature.power(privateExponent, modulus: modulus).serialize()
//            }
            throw CitadelError.unsupported
        }
        
        internal func generatedSharedSecret(with publicKey: PublicKey, modulus: BigUInt) -> Data {
            let secret = CCryptoBoringSSL_BN_new()
            defer { CCryptoBoringSSL_BN_free(secret) }
            
            let ctx = CCryptoBoringSSL_BN_CTX_new()
            defer { CCryptoBoringSSL_BN_CTX_free(ctx) }
            
            let group = CCryptoBoringSSL_BN_bin2bn(dh14p, dh14p.count, nil)!
            defer { CCryptoBoringSSL_BN_free(group) }
            CCryptoBoringSSL_BN_mod_exp(
                secret,
                publicKey.modulus,
                privateExponent,
                group,
                ctx
            )
            
            var array = [UInt8]()
            array.reserveCapacity(Int(CCryptoBoringSSL_BN_num_bytes(secret)))
            CCryptoBoringSSL_BN_bn2bin(secret, &array)
            return Data(array)
        }
    }
    
    // MARK: - RSA Certificate Public Key Types
    
    /// Base class for RSA certificate public keys
    public class CertificatePublicKey: PublicKey {
        public override class var publicKeyPrefix: String {
            fatalError("Subclasses must override publicKeyPrefix")
        }
    }
    
    /// RSA certificate with SHA-1 (legacy)
    public final class SHA1CertificatePublicKey: CertificatePublicKey {
        public override class var publicKeyPrefix: String { "ssh-rsa-cert-v01@openssh.com" }
    }
    
    /// RSA certificate with SHA-256
    public final class SHA256CertificatePublicKey: CertificatePublicKey {
        public override class var publicKeyPrefix: String { "rsa-sha2-256-cert-v01@openssh.com" }
    }
    
    /// RSA certificate with SHA-512
    public final class SHA512CertificatePublicKey: CertificatePublicKey {
        public override class var publicKeyPrefix: String { "rsa-sha2-512-cert-v01@openssh.com" }
    }
}

public struct RSAError: Error {
    let message: String
    
    static let messageRepresentativeOutOfRange = RSAError(message: "message representative out of range")
    static let ciphertextRepresentativeOutOfRange = RSAError(message: "ciphertext representative out of range")
    static let signatureRepresentativeOutOfRange = RSAError(message: "signature representative out of range")
    static let invalidPem = RSAError(message: "invalid PEM")
    static let pkcs1Error = RSAError(message: "PKCS1Error")
}

extension BigUInt {
    public static func randomPrime(bits: Int) -> BigUInt {
        while true {
            var privateExponent = BigUInt.randomInteger(withExactWidth: bits)
            privateExponent |= 1
            
            if privateExponent.isPrime() {
                return privateExponent
            }
        }
    }
    
    fileprivate init(boringSSL bignum: UnsafeMutablePointer<BIGNUM>) {
        var data = [UInt8](repeating: 0, count: Int(CCryptoBoringSSL_BN_num_bytes(bignum)))
        CCryptoBoringSSL_BN_bn2bin(bignum, &data)
        self.init(Data(data))
    }
}

extension BigUInt {
    public static let diffieHellmanGroup14 = BigUInt(Data([
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
        0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
        0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
        0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
        0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
        0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
        0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
        0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
        0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
        0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
        0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    ] as [UInt8]))
}

extension ByteBuffer {
    @discardableResult
    mutating func readPositiveMPInt() -> BigUInt? {
        guard
            let length = readInteger(as: UInt32.self),
            let data = readData(length: Int(length))
        else {
            return nil
        }
        
        return BigUInt(data)
    }
    
    @discardableResult
    mutating func writePositiveMPInt<Buffer: Collection>(_ value: Buffer) -> Int where Buffer.Element == UInt8 {
        // A positive MPInt must have its high bit set to zero, and not have leading zero bytes unless it needs that
        // high bit set to zero. We address this by dropping all the leading zero bytes in the collection first.
        let trimmed = value.drop(while: { $0 == 0 })
        let needsLeadingZero = ((trimmed.first ?? 0) & 0x80) == 0x80

        // Now we write the length.
        var writtenBytes: Int

        if needsLeadingZero {
            writtenBytes = self.writeInteger(UInt32(trimmed.count + 1))
            writtenBytes += self.writeInteger(UInt8(0))
        } else {
            writtenBytes = self.writeInteger(UInt32(trimmed.count))
        }

        writtenBytes += self.writeBytes(trimmed)
        return writtenBytes
    }
    
    /// Writes the given bytes as an SSH string at the writer index. Moves the writer index forward.
    @discardableResult
    mutating func writeSSHString<Buffer: Collection>(_ value: Buffer) -> Int where Buffer.Element == UInt8 {
        let writtenBytes = self.setSSHString(value, at: self.writerIndex)
        self.moveWriterIndex(forwardBy: writtenBytes)
        return writtenBytes
    }
    
    /// Sets the given bytes as an SSH string at the given offset. Does not mutate the writer index.
    @discardableResult
    mutating func setSSHString<Buffer: Collection>(_ value: Buffer, at offset: Int) -> Int where Buffer.Element == UInt8 {
        // RFC 4251 § 5:
        //
        // > Arbitrary length binary string.  Strings are allowed to contain
        // > arbitrary binary data, including null characters and 8-bit
        // > characters.  They are stored as a uint32 containing its length
        // > (number of bytes that follow) and zero (= empty string) or more
        // > bytes that are the value of the string.  Terminating null
        // > characters are not used.
        let lengthLength = self.setInteger(UInt32(value.count), at: offset)
        let valueLength = self.setBytes(value, at: offset + lengthLength)
        return lengthLength + valueLength
    }
    
    /// Sets the readable bytes of a ByteBuffer as an SSH string at the given offset. Does not mutate the writer index.
    @discardableResult
    mutating func setSSHString(_ value: ByteBuffer, at offset: Int) -> Int {
        // RFC 4251 § 5:
        //
        // > Arbitrary length binary string.  Strings are allowed to contain
        // > arbitrary binary data, including null characters and 8-bit
        // > characters.  They are stored as a uint32 containing its length
        // > (number of bytes that follow) and zero (= empty string) or more
        // > bytes that are the value of the string.  Terminating null
        // > characters are not used.
        let lengthLength = self.setInteger(UInt32(value.readableBytes), at: offset)
        let valueLength = self.setBuffer(value, at: offset + lengthLength)
        return lengthLength + valueLength
    }
}
