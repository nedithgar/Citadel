import Crypto
import Foundation
import NIO
import NIOSSH
import XCTest
@testable import Citadel

final class CertificateSecurityValidationTests: XCTestCase {
    func testCertificateIsRejectedBeforeValidAfter() throws {
        let validAfter: UInt64 = 100
        let fixture = try self.makeCertificate(
            validAfter: validAfter,
            validBefore: 200
        )

        XCTAssertThrowsError(
            try fixture.certificate.validateForAuthentication(
                username: "testuser",
                currentTime: Date(timeIntervalSince1970: TimeInterval(validAfter - 1))
            )
        ) { error in
            guard let error = error as? SSHCertificateError,
                  case .notYetValid(let reportedValidAfter) = error
            else {
                return XCTFail("Expected notYetValid, got \(error)")
            }
            XCTAssertEqual(
                reportedValidAfter,
                Date(timeIntervalSince1970: TimeInterval(validAfter))
            )
        }

        XCTAssertNoThrow(
            try fixture.certificate.validateForAuthentication(
                username: "testuser",
                currentTime: Date(timeIntervalSince1970: TimeInterval(validAfter))
            )
        )
    }

    func testCertificateIsRejectedAtValidBefore() throws {
        let validBefore: UInt64 = 200
        let fixture = try self.makeCertificate(
            validAfter: 100,
            validBefore: validBefore
        )

        XCTAssertNoThrow(
            try fixture.certificate.validateForAuthentication(
                username: "testuser",
                currentTime: Date(timeIntervalSince1970: TimeInterval(validBefore - 1))
            )
        )
        XCTAssertThrowsError(
            try fixture.certificate.validateForAuthentication(
                username: "testuser",
                currentTime: Date(timeIntervalSince1970: TimeInterval(validBefore))
            )
        ) { error in
            guard let error = error as? SSHCertificateError,
                  case .expired(let reportedValidBefore) = error
            else {
                return XCTFail("Expected expired, got \(error)")
            }
            XCTAssertEqual(
                reportedValidBefore,
                Date(timeIntervalSince1970: TimeInterval(validBefore))
            )
        }
    }

    func testUserAuthenticationValidationRejectsHostCertificate() throws {
        let fixture = try self.makeCertificate(
            type: .host,
            validPrincipals: ["example.com"],
            validAfter: 0,
            validBefore: .max
        )

        XCTAssertThrowsError(
            try SSHAuthenticationMethod.ed25519Certificate(
                username: "testuser",
                privateKey: fixture.privateKey,
                certificate: fixture.certificate,
                validateCertificate: true
            )
        ) { error in
            guard let error = error as? SSHCertificateError,
                  case .invalidCertificateType = error
            else {
                return XCTFail("Expected invalidCertificateType, got \(error)")
            }
        }
    }

    private func makeCertificate(
        type: NIOSSHCertifiedPublicKey.CertificateType = .user,
        validPrincipals: [String] = ["testuser"],
        validAfter: UInt64,
        validBefore: UInt64
    ) throws -> (privateKey: Curve25519.Signing.PrivateKey, certificate: NIOSSHCertifiedPublicKey) {
        let privateKey = Curve25519.Signing.PrivateKey()
        let caPrivateKey = NIOSSHPrivateKey(ed25519Key: .init())
        let placeholderSignature = try caPrivateKey.sign(
            digest: SHA256.hash(data: Data("certificate-security-validation".utf8))
        )
        let certificate = try NIOSSHCertifiedPublicKey(
            nonce: ByteBuffer(repeating: 0xa5, count: 32),
            serial: 1,
            type: type,
            key: NIOSSHPrivateKey(ed25519Key: privateKey).publicKey,
            keyID: "certificate-security-validation",
            validPrincipals: validPrincipals,
            validAfter: validAfter,
            validBefore: validBefore,
            criticalOptions: [:],
            extensions: [:],
            signatureKey: caPrivateKey.publicKey,
            signature: placeholderSignature
        )
        return (privateKey, certificate)
    }
}
