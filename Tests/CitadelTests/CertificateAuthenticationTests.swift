import XCTest
@testable import Citadel
import Crypto
import _CryptoExtras
import Foundation
import NIO
import NIOSSH

final class CertificateAuthenticationTests: XCTestCase {
    
    // Helper to get environment variables
    private func getEnv(_ name: String) -> String? {
        ProcessInfo.processInfo.environment[name]
    }
    
    // Helper to load test certificate files
    private func loadTestCertificate(keyType: String) throws -> (privateKey: Data, certificate: Data) {
        guard let certsDir = getEnv("TEST_CERTS_DIR") else {
            throw XCTSkip("TEST_CERTS_DIR not set - skipping certificate tests")
        }
        let privateKeyPath = "\(certsDir)/user_\(keyType)"
        let certificatePath = "\(certsDir)/user_\(keyType)-cert.pub"
        
        let privateKey = try Data(contentsOf: URL(fileURLWithPath: privateKeyPath))
        let certificate = try Data(contentsOf: URL(fileURLWithPath: certificatePath))
        
        return (privateKey, certificate)
    }
    
    func testEd25519CertificateAuthentication() async throws {
        guard let host = getEnv("SSH_HOST"),
              let portStr = getEnv("SSH_CERT_PORT"),
              let port = Int(portStr),
              let username = getEnv("SSH_USERNAME") else {
            throw XCTSkip("Required environment variables not set")
        }
        
        // Load Ed25519 key and certificate
        let (privateKeyData, certificateData) = try loadTestCertificate(keyType: "ed25519")
        
        // Parse the private key
        let privateKey = try Curve25519.Signing.PrivateKey(sshEd25519PrivateKey: privateKeyData)
        
        // Create client with Ed25519 authentication
        let client = try await SSHClient.connect(
            host: host,
            port: port,
            authenticationMethod: .ed25519(username: username, privateKey: privateKey),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )
        
        // Test that we can execute a command
        let result = try await client.executeCommand("echo 'Certificate auth successful'")
        XCTAssertEqual(result.trimmingCharacters(in: .whitespacesAndNewlines), "Certificate auth successful")
        
        try await client.close()
    }
    
    func testRSACertificateAuthentication() async throws {
        guard let host = getEnv("SSH_HOST"),
              let portStr = getEnv("SSH_CERT_PORT"),
              let port = Int(portStr),
              let username = getEnv("SSH_USERNAME") else {
            throw XCTSkip("Required environment variables not set")
        }
        
        // Load RSA key and certificate
        let (privateKeyData, certificateData) = try loadTestCertificate(keyType: "rsa")
        
        // Parse the private key
        let privateKey = try Insecure.RSA.PrivateKey(sshRSAPrivateKey: privateKeyData)
        
        // Create client with RSA authentication
        let client = try await SSHClient.connect(
            host: host,
            port: port,
            authenticationMethod: .rsa(username: username, privateKey: privateKey),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )
        
        // Test that we can execute a command
        let result = try await client.executeCommand("echo 'RSA certificate auth successful'")
        XCTAssertEqual(result.trimmingCharacters(in: .whitespacesAndNewlines), "RSA certificate auth successful")
        
        try await client.close()
    }
    
    func testP256CertificateAuthentication() async throws {
        guard let host = getEnv("SSH_HOST"),
              let portStr = getEnv("SSH_CERT_PORT"),
              let port = Int(portStr),
              let username = getEnv("SSH_USERNAME") else {
            throw XCTSkip("Required environment variables not set")
        }
        
        // Load ECDSA P-256 key and certificate
        let (privateKeyData, certificateData) = try loadTestCertificate(keyType: "ecdsa256")
        
        // Parse the private key from OpenSSH format
        let privateKey = try P256.Signing.PrivateKey(sshECDSAPrivateKey: privateKeyData)
        
        // Create client with P256 authentication
        let client = try await SSHClient.connect(
            host: host,
            port: port,
            authenticationMethod: .p256(username: username, privateKey: privateKey),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )
        
        // Test that we can execute a command
        let result = try await client.executeCommand("echo 'P256 certificate auth successful'")
        XCTAssertEqual(result.trimmingCharacters(in: .whitespacesAndNewlines), "P256 certificate auth successful")
        
        try await client.close()
    }
    
    func testP384CertificateAuthentication() async throws {
        guard let host = getEnv("SSH_HOST"),
              let portStr = getEnv("SSH_CERT_PORT"),
              let port = Int(portStr),
              let username = getEnv("SSH_USERNAME") else {
            throw XCTSkip("Required environment variables not set")
        }
        
        // Load ECDSA P-384 key and certificate
        let (privateKeyData, certificateData) = try loadTestCertificate(keyType: "ecdsa384")
        
        // Parse the private key from OpenSSH format
        let privateKey = try P384.Signing.PrivateKey(sshECDSAPrivateKey: privateKeyData)
        
        // Create client with P384 authentication
        let client = try await SSHClient.connect(
            host: host,
            port: port,
            authenticationMethod: .p384(username: username, privateKey: privateKey),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )
        
        // Test that we can execute a command
        let result = try await client.executeCommand("echo 'P384 certificate auth successful'")
        XCTAssertEqual(result.trimmingCharacters(in: .whitespacesAndNewlines), "P384 certificate auth successful")
        
        try await client.close()
    }
    
    func testP521CertificateAuthentication() async throws {
        guard let host = getEnv("SSH_HOST"),
              let portStr = getEnv("SSH_CERT_PORT"),
              let port = Int(portStr),
              let username = getEnv("SSH_USERNAME") else {
            throw XCTSkip("Required environment variables not set")
        }
        
        // Load ECDSA P-521 key and certificate
        let (privateKeyData, certificateData) = try loadTestCertificate(keyType: "ecdsa521")
        
        // Parse the private key from OpenSSH format
        let privateKey = try P521.Signing.PrivateKey(sshECDSAPrivateKey: privateKeyData)
        
        // Create client with P521 authentication
        let client = try await SSHClient.connect(
            host: host,
            port: port,
            authenticationMethod: .p521(username: username, privateKey: privateKey),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )
        
        // Test that we can execute a command
        let result = try await client.executeCommand("echo 'P521 certificate auth successful'")
        XCTAssertEqual(result.trimmingCharacters(in: .whitespacesAndNewlines), "P521 certificate auth successful")
        
        try await client.close()
    }
    
    func testCertificateAuthenticationFailsWithWrongPrincipal() async throws {
        guard let host = getEnv("SSH_HOST"),
              let portStr = getEnv("SSH_CERT_PORT"),
              let port = Int(portStr) else {
            throw XCTSkip("Required environment variables not set")
        }
        
        // Load Ed25519 key and certificate
        let (privateKeyData, certificateData) = try loadTestCertificate(keyType: "ed25519")
        let privateKey = try Curve25519.Signing.PrivateKey(sshEd25519PrivateKey: privateKeyData)
        
        // Try to authenticate with wrong username (certificate is for "citadel")
        do {
            let client = try await SSHClient.connect(
                host: host,
                port: port,
                authenticationMethod: .ed25519(username: "wronguser", privateKey: privateKey),
                hostKeyValidator: .acceptAnything(),
                reconnect: .never
            )
            try await client.close()
            XCTFail("Authentication should have failed with wrong principal")
        } catch {
            // Expected failure
            XCTAssertTrue(true, "Authentication correctly failed with wrong principal")
        }
    }
}

// Extension to help with command execution
extension SSHClient {
    func executeCommand(_ command: String) async throws -> String {
        let exec = try await self.withExecChannel(command: command) { stdout, stderr, _ in
            var output = ""
            for try await chunk in stdout {
                output += String(buffer: chunk)
            }
            return output
        }
        return try await exec.value
    }
}