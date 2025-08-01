import Foundation

/// Errors that can occur during SSH certificate operations
public enum SSHCertificateError: LocalizedError {
    case invalidCertificateData
    case invalidCertificateType
    case principalNotAllowed(String)
    case certificateExpired
    case certificateNotYetValid
    case sourceAddressNotAllowed(String)
    case invalidRSAKeySize(Int)
    case signatureAlgorithmNotAllowed(String)
    case untrustedCA
    case invalidSignature
    case parsingFailed(String)
    case notYetValid(validAfter: Date)
    case expired(validBefore: Date)
    case noPrincipals
    case rsaKeyTooSmall(bits: Int, minimum: Int)
    case unknownCriticalOption(String)
    
    public var errorDescription: String? {
        switch self {
        case .invalidCertificateData:
            return "Invalid certificate data"
        case .invalidCertificateType:
            return "Invalid certificate type for this operation"
        case .principalNotAllowed(let principal):
            return "Principal '\(principal)' is not allowed"
        case .certificateExpired:
            return "Certificate has expired"
        case .certificateNotYetValid:
            return "Certificate is not yet valid"
        case .sourceAddressNotAllowed(let address):
            return "Source address '\(address)' is not allowed"
        case .invalidRSAKeySize(let size):
            return "RSA key size \(size) is below minimum allowed"
        case .signatureAlgorithmNotAllowed(let algorithm):
            return "Signature algorithm '\(algorithm)' is not allowed"
        case .untrustedCA:
            return "Certificate is not signed by a trusted CA"
        case .invalidSignature:
            return "Certificate signature verification failed"
        case .parsingFailed(let reason):
            return "Certificate parsing failed: \(reason)"
        case .notYetValid(let validAfter):
            return "Certificate is not yet valid (valid after: \(validAfter))"
        case .expired(let validBefore):
            return "Certificate has expired (valid before: \(validBefore))"
        case .noPrincipals:
            return "Certificate has no valid principals"
        case .rsaKeyTooSmall(let bits, let minimum):
            return "RSA key size \(bits) is below minimum required \(minimum)"
        case .unknownCriticalOption(let option):
            return "Unknown critical option: \(option)"
        }
    }
}