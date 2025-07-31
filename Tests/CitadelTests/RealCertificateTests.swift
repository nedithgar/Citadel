import XCTest
@testable import Citadel
import Crypto
import _CryptoExtras
import Foundation
import NIO
import NIOSSH

final class RealCertificateTests: XCTestCase {
    
    // Helper to run shell commands
    private func runCommand(_ command: String) throws -> String {
        let process = Process()
        let pipe = Pipe()
        
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-c", command]
        process.standardOutput = pipe
        process.standardError = pipe
        
        try process.run()
        process.waitUntilExit()
        
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "Command failed", code: Int(process.terminationStatus), userInfo: [
                NSLocalizedDescriptionKey: String(data: data, encoding: .utf8) ?? "Unknown error"
            ])
        }
        
        return String(data: data, encoding: .utf8) ?? ""
    }
    
    // Create a temporary directory for test files
    private func createTempDirectory() throws -> URL {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("citadel-cert-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        return tempDir
    }
    
    // Clean up temporary directory
    private func cleanup(_ directory: URL) {
        try? FileManager.default.removeItem(at: directory)
    }
    
    // Test generating and using real Ed25519 certificates
    func testRealEd25519Certificate() throws {
        let tempDir = try createTempDirectory()
        defer { cleanup(tempDir) }
        
        let caKeyPath = tempDir.appendingPathComponent("ca_key")
        let userKeyPath = tempDir.appendingPathComponent("user_key")
        let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
        
        // Generate CA key
        _ = try runCommand("ssh-keygen -t ed25519 -f \(caKeyPath.path) -N ''")
        
        // Generate user key
        _ = try runCommand("ssh-keygen -t ed25519 -f \(userKeyPath.path) -N ''")
        
        // Sign the user key to create a certificate
        _ = try runCommand("""
            ssh-keygen -s \(caKeyPath.path) \
                -I "test-user" \
                -n testuser,admin \
                -V -5m:+1h \
                \(userKeyPath.path).pub
        """)
        
        // Read the certificate file
        let certData = try Data(contentsOf: certPath)
        let certString = String(data: certData, encoding: .utf8)!
        
        // Extract the base64 certificate data
        let parts = certString.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ")
        guard parts.count >= 2,
              parts[0] == "ssh-ed25519-cert-v01@openssh.com",
              let certBase64Data = Data(base64Encoded: String(parts[1])) else {
            XCTFail("Invalid certificate format")
            return
        }
        
        // Parse the certificate
        let certificate = try Ed25519.CertificatePublicKey(certificateData: certBase64Data)
        
        // Verify certificate properties
        XCTAssertEqual(certificate.certificate.keyId, "test-user")
        XCTAssertTrue(certificate.certificate.validPrincipals.contains("testuser"))
        XCTAssertTrue(certificate.certificate.validPrincipals.contains("admin"))
        
        // For this test, we'll verify the certificate was created successfully
        XCTAssertTrue(FileManager.default.fileExists(atPath: certPath.path))
        XCTAssertNotNil(certificate)
    }
    
    // Test generating and using real RSA certificates
    func testRealRSACertificate() throws {
        let tempDir = try createTempDirectory()
        defer { cleanup(tempDir) }
        
        let caKeyPath = tempDir.appendingPathComponent("ca_key")
        let userKeyPath = tempDir.appendingPathComponent("user_key")
        let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
        
        // Generate CA key (Ed25519 for signing)
        _ = try runCommand("ssh-keygen -t ed25519 -f \(caKeyPath.path) -N ''")
        
        // Generate user RSA key
        _ = try runCommand("ssh-keygen -t rsa -b 2048 -f \(userKeyPath.path) -N ''")
        
        // Sign the user key to create a certificate
        _ = try runCommand("""
            ssh-keygen -s \(caKeyPath.path) \
                -I "test-rsa-user" \
                -n testuser \
                -V -5m:+1h \
                -O clear \
                -O permit-X11-forwarding \
                -O permit-agent-forwarding \
                -O permit-port-forwarding \
                -O permit-pty \
                -O permit-user-rc \
                \(userKeyPath.path).pub
        """)
        
        // Read the certificate file
        let certData = try Data(contentsOf: certPath)
        let certString = String(data: certData, encoding: .utf8)!
        
        // Extract the base64 certificate data
        let parts = certString.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ")
        guard parts.count >= 2,
              let certBase64Data = Data(base64Encoded: String(parts[1])) else {
            XCTFail("Invalid certificate format")
            return
        }
        
        // Parse the certificate with the appropriate algorithm
        // ssh-keygen creates ssh-rsa-cert-v01@openssh.com which corresponds to .sha1Cert
        let certificate = try Insecure.RSA.CertificatePublicKey(
            certificateData: certBase64Data,
            algorithm: .sha1Cert
        )
        
        // Verify certificate properties
        XCTAssertEqual(certificate.certificate.keyId, "test-rsa-user")
        XCTAssertTrue(certificate.certificate.validPrincipals.contains("testuser"))
        
        // Verify extensions
        let extensionNames = certificate.certificate.extensions.map { $0.0 }
        XCTAssertTrue(extensionNames.contains("permit-X11-forwarding"))
        XCTAssertTrue(extensionNames.contains("permit-agent-forwarding"))
        XCTAssertTrue(extensionNames.contains("permit-port-forwarding"))
        XCTAssertTrue(extensionNames.contains("permit-pty"))
        XCTAssertTrue(extensionNames.contains("permit-user-rc"))
    }
    
    // Test generating and using real ECDSA certificates
    func testRealECDSACertificate() throws {
        let tempDir = try createTempDirectory()
        defer { cleanup(tempDir) }
        
        let caKeyPath = tempDir.appendingPathComponent("ca_key")
        let userKeyPath = tempDir.appendingPathComponent("user_key")
        let certPath = tempDir.appendingPathComponent("user_key-cert.pub")
        
        // Generate CA key
        _ = try runCommand("ssh-keygen -t ed25519 -f \(caKeyPath.path) -N ''")
        
        // Generate user ECDSA key (P256)
        _ = try runCommand("ssh-keygen -t ecdsa -b 256 -f \(userKeyPath.path) -N ''")
        
        // Sign the user key to create a certificate
        _ = try runCommand("""
            ssh-keygen -s \(caKeyPath.path) \
                -I "test-ecdsa-user" \
                -n testuser \
                -V -5m:+1h \
                \(userKeyPath.path).pub
        """)
        
        // Read the certificate file
        let certData = try Data(contentsOf: certPath)
        let certString = String(data: certData, encoding: .utf8)!
        
        // Extract the base64 certificate data
        let parts = certString.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ")
        guard parts.count >= 2,
              parts[0] == "ecdsa-sha2-nistp256-cert-v01@openssh.com",
              let certBase64Data = Data(base64Encoded: String(parts[1])) else {
            XCTFail("Invalid certificate format")
            return
        }
        
        // Parse the certificate
        let certificate = try P256.Signing.CertificatePublicKey(certificateData: certBase64Data)
        
        // Verify certificate properties
        XCTAssertEqual(certificate.certificate.keyId, "test-ecdsa-user")
        XCTAssertTrue(certificate.certificate.validPrincipals.contains("testuser"))
    }
    
    // Test certificate validity and expiration
    func testCertificateExpiration() throws {
        let tempDir = try createTempDirectory()
        defer { cleanup(tempDir) }
        
        let caKeyPath = tempDir.appendingPathComponent("ca_key")
        let userKeyPath = tempDir.appendingPathComponent("user_key")
        let expiredKeyPath = tempDir.appendingPathComponent("expired_key")
        let futureKeyPath = tempDir.appendingPathComponent("future_key")
        
        // Generate CA key
        _ = try runCommand("ssh-keygen -t ed25519 -f \(caKeyPath.path) -N ''")
        
        // Generate user key
        _ = try runCommand("ssh-keygen -t ed25519 -f \(userKeyPath.path) -N ''")
        
        // Copy the keys for expired and future certificates
        let pubKeyPath = userKeyPath.appendingPathExtension("pub")
        let privKeyPath = userKeyPath
        
        try FileManager.default.copyItem(at: pubKeyPath, to: expiredKeyPath.appendingPathExtension("pub"))
        try FileManager.default.copyItem(at: privKeyPath, to: expiredKeyPath)
        
        try FileManager.default.copyItem(at: pubKeyPath, to: futureKeyPath.appendingPathExtension("pub"))
        try FileManager.default.copyItem(at: privKeyPath, to: futureKeyPath)
        
        // Create an expired certificate
        _ = try runCommand("""
            ssh-keygen -s \(caKeyPath.path) \
                -I "expired-cert" \
                -n testuser \
                -V -2h:-1h \
                \(expiredKeyPath.path).pub
        """)
        
        // Create a future certificate
        _ = try runCommand("""
            ssh-keygen -s \(caKeyPath.path) \
                -I "future-cert" \
                -n testuser \
                -V +1h:+2h \
                \(futureKeyPath.path).pub
        """)
        
        // Read and parse expired certificate
        let expiredCertPath = tempDir.appendingPathComponent("expired_key-cert.pub")
        let expiredData = try Data(contentsOf: expiredCertPath)
        let expiredString = String(data: expiredData, encoding: .utf8)!
        let expiredParts = expiredString.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ")
        
        if let expiredBase64 = Data(base64Encoded: String(expiredParts[1])) {
            let expiredCert = try Ed25519.CertificatePublicKey(certificateData: expiredBase64)
            let now = UInt64(Date().timeIntervalSince1970)
            XCTAssertTrue(expiredCert.certificate.validBefore < now, "Certificate should be expired")
        }
        
        // Read and parse future certificate
        let futureCertPath = tempDir.appendingPathComponent("future_key-cert.pub")
        let futureData = try Data(contentsOf: futureCertPath)
        let futureString = String(data: futureData, encoding: .utf8)!
        let futureParts = futureString.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ")
        
        if let futureBase64 = Data(base64Encoded: String(futureParts[1])) {
            let futureCert = try Ed25519.CertificatePublicKey(certificateData: futureBase64)
            let now = UInt64(Date().timeIntervalSince1970)
            XCTAssertTrue(futureCert.certificate.validAfter > now, "Certificate should not be valid yet")
        }
    }
    
    // Test host certificates
    func testHostCertificate() throws {
        let tempDir = try createTempDirectory()
        defer { cleanup(tempDir) }
        
        let caKeyPath = tempDir.appendingPathComponent("ca_key")
        let hostKeyPath = tempDir.appendingPathComponent("host_key")
        let certPath = tempDir.appendingPathComponent("host_key-cert.pub")
        
        // Generate CA key
        _ = try runCommand("ssh-keygen -t ed25519 -f \(caKeyPath.path) -N ''")
        
        // Generate host key
        _ = try runCommand("ssh-keygen -t ed25519 -f \(hostKeyPath.path) -N ''")
        
        // Sign the host key to create a host certificate
        _ = try runCommand("""
            ssh-keygen -s \(caKeyPath.path) \
                -I "test-host" \
                -h \
                -n example.com,*.example.com,10.0.0.1 \
                -V -5m:+365d \
                \(hostKeyPath.path).pub
        """)
        
        // Read the certificate file
        let certData = try Data(contentsOf: certPath)
        let certString = String(data: certData, encoding: .utf8)!
        
        // Extract the base64 certificate data
        let parts = certString.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ")
        guard parts.count >= 2,
              let certBase64Data = Data(base64Encoded: String(parts[1])) else {
            XCTFail("Invalid certificate format")
            return
        }
        
        // Parse the certificate
        let certificate = try Ed25519.CertificatePublicKey(certificateData: certBase64Data)
        
        // Verify it's a host certificate (type 2)
        XCTAssertEqual(certificate.certificate.type, .host, "Should be a host certificate")
        XCTAssertEqual(certificate.certificate.keyId, "test-host")
        
        // Verify valid principals (hostnames)
        XCTAssertTrue(certificate.certificate.validPrincipals.contains("example.com"))
        XCTAssertTrue(certificate.certificate.validPrincipals.contains("*.example.com"))
        XCTAssertTrue(certificate.certificate.validPrincipals.contains("10.0.0.1"))
    }
}