import Foundation
import XCTest

/// Helper class to generate SSH certificates dynamically during test runs
enum SSHCertificateGenerator {
    
    /// Temporary directory for generated certificates
    static var tempDirectory: URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("CitadelTestCerts-\(ProcessInfo.processInfo.processIdentifier)")
    }
    
    /// Setup the temporary directory
    static func setUp() throws {
        try FileManager.default.createDirectory(at: tempDirectory, withIntermediateDirectories: true)
    }
    
    /// Clean up the temporary directory
    static func tearDown() throws {
        if FileManager.default.fileExists(atPath: tempDirectory.path) {
            try FileManager.default.removeItem(at: tempDirectory)
        }
    }
    
    /// Check if ssh-keygen is available
    static func ensureSSHKeygenAvailable() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        process.arguments = ["ssh-keygen"]
        
        let pipe = Pipe()
        process.standardOutput = pipe
        
        try process.run()
        process.waitUntilExit()
        
        guard process.terminationStatus == 0 else {
            throw XCTSkip("ssh-keygen not found in PATH")
        }
    }
    
    /// Generate a CA key pair
    static func generateCAKeyPair(type: String = "ed25519", name: String = "ca") throws -> (privateKey: URL, publicKey: URL) {
        let privateKeyPath = tempDirectory.appendingPathComponent("\(name)_\(type)")
        let publicKeyPath = tempDirectory.appendingPathComponent("\(name)_\(type).pub")
        
        // Remove existing files to avoid prompts
        try? FileManager.default.removeItem(at: privateKeyPath)
        try? FileManager.default.removeItem(at: publicKeyPath)
        
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = [
            "-t", type,
            "-f", privateKeyPath.path,
            "-N", "", // No passphrase
            "-C", "test-ca-\(type)",
            "-q" // Quiet mode
        ]
        
        try process.run()
        process.waitUntilExit()
        
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "SSHCertificateGenerator", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "Failed to generate CA key pair"
            ])
        }
        
        return (privateKeyPath, publicKeyPath)
    }
    
    /// Generate a user key pair
    static func generateUserKeyPair(type: String, name: String) throws -> (privateKey: URL, publicKey: URL) {
        let privateKeyPath = tempDirectory.appendingPathComponent("\(name)_\(type)")
        let publicKeyPath = tempDirectory.appendingPathComponent("\(name)_\(type).pub")
        
        // Remove existing files to avoid prompts
        try? FileManager.default.removeItem(at: privateKeyPath)
        try? FileManager.default.removeItem(at: publicKeyPath)
        
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = [
            "-t", type,
            "-f", privateKeyPath.path,
            "-N", "", // No passphrase
            "-C", "test-\(name)-\(type)",
            "-q" // Quiet mode
        ]
        
        if type == "rsa" {
            process.arguments?.append(contentsOf: ["-b", "2048"]) // RSA key size
        }
        
        try process.run()
        process.waitUntilExit()
        
        guard process.terminationStatus == 0 else {
            throw NSError(domain: "SSHCertificateGenerator", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "Failed to generate user key pair"
            ])
        }
        
        return (privateKeyPath, publicKeyPath)
    }
    
    /// Generate a certificate
    static func generateCertificate(
        userPublicKey: URL,
        caPrivateKey: URL,
        serial: UInt64,
        keyID: String,
        principals: [String],
        certType: CertificateType = .user,
        validityDuration: TimeInterval = 3600, // 1 hour default
        criticalOptions: [String: String]? = nil,
        extensions: [String]? = nil
    ) throws -> URL {
        let certificatePath = URL(fileURLWithPath: userPublicKey.path.replacingOccurrences(of: ".pub", with: "-cert.pub"))
        
        var arguments = [
            "-s", caPrivateKey.path,
            "-I", keyID,
            "-n", principals.joined(separator: ","),
            "-z", String(serial),
            "-V", "+\(Int(validityDuration))s" // Validity from now + duration in seconds
        ]
        
        // Add certificate type
        if certType == .host {
            arguments.insert("-h", at: 0)
        }
        
        // Add critical options
        if let criticalOptions = criticalOptions {
            for (key, value) in criticalOptions {
                arguments.append(contentsOf: ["-O", "\(key)=\(value)"])
            }
        }
        
        // Add extensions
        if let extensions = extensions {
            for ext in extensions {
                arguments.append(contentsOf: ["-O", ext])
            }
        }
        
        // Add the public key file at the end
        arguments.append(userPublicKey.path)
        
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = arguments
        
        let errorPipe = Pipe()
        process.standardError = errorPipe
        
        try process.run()
        process.waitUntilExit()
        
        guard process.terminationStatus == 0 else {
            let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
            let errorString = String(data: errorData, encoding: .utf8) ?? "Unknown error"
            throw NSError(domain: "SSHCertificateGenerator", code: 3, userInfo: [
                NSLocalizedDescriptionKey: "Failed to generate certificate: \(errorString)"
            ])
        }
        
        return certificatePath
    }
    
    enum CertificateType {
        case user
        case host
    }
    
    /// Common certificate configurations for tests
    struct TestCertificateConfig {
        let keyType: String
        let serial: UInt64
        let keyID: String
        let principals: [String]
        let certType: CertificateType
        let validityDuration: TimeInterval
        let criticalOptions: [String: String]?
        let extensions: [String]?
        
        static func ed25519User() -> TestCertificateConfig {
            TestCertificateConfig(
                keyType: "ed25519",
                serial: 1,
                keyID: "test-user-ed25519",
                principals: ["testuser", "alice"],
                certType: .user,
                validityDuration: 7200, // 2 hours to avoid expiration during tests
                criticalOptions: nil,
                extensions: nil
            )
        }
        
        static func p256User() -> TestCertificateConfig {
            TestCertificateConfig(
                keyType: "ecdsa",
                serial: 2,
                keyID: "test-user-p256",
                principals: ["testuser"],
                certType: .user,
                validityDuration: 7200,
                criticalOptions: nil,
                extensions: nil
            )
        }
        
        static func p384User() -> TestCertificateConfig {
            TestCertificateConfig(
                keyType: "ecdsa-sha2-nistp384",
                serial: 3,
                keyID: "test-user-p384",
                principals: ["testuser", "admin"],
                certType: .user,
                validityDuration: 7200,
                criticalOptions: nil,
                extensions: nil
            )
        }
        
        static func p521User() -> TestCertificateConfig {
            TestCertificateConfig(
                keyType: "ecdsa-sha2-nistp521",
                serial: 4,
                keyID: "test-user-p521",
                principals: ["testuser"],
                certType: .user,
                validityDuration: 7200,
                criticalOptions: nil,
                extensions: nil
            )
        }
        
        static func rsaUser() -> TestCertificateConfig {
            TestCertificateConfig(
                keyType: "rsa",
                serial: 5,
                keyID: "test-user-rsa",
                principals: ["testuser"],
                certType: .user,
                validityDuration: 7200,
                criticalOptions: nil,
                extensions: nil
            )
        }
        
        static func hostCert() -> TestCertificateConfig {
            TestCertificateConfig(
                keyType: "ed25519",
                serial: 100,
                keyID: "test-host",
                principals: ["*.example.com", "example.com"],
                certType: .host,
                validityDuration: 7200,
                criticalOptions: nil,
                extensions: nil
            )
        }
        
        static func restrictedUser() -> TestCertificateConfig {
            TestCertificateConfig(
                keyType: "ed25519",
                serial: 202,
                keyID: "restricted-cert",
                principals: ["testuser"],
                certType: .user,
                validityDuration: 7200,
                criticalOptions: [
                    "force-command": "/bin/date",
                    "source-address": "192.168.1.0/24,10.0.0.1"
                ],
                extensions: nil
            )
        }
        
        static func limitedPrincipals() -> TestCertificateConfig {
            TestCertificateConfig(
                keyType: "ed25519",
                serial: 203,
                keyID: "limited-cert",
                principals: ["alice", "bob"],
                certType: .user,
                validityDuration: 7200,
                criticalOptions: nil,
                extensions: nil
            )
        }
        
        static func allExtensions() -> TestCertificateConfig {
            TestCertificateConfig(
                keyType: "ed25519",
                serial: 204,
                keyID: "full-cert",
                principals: ["testuser"],
                certType: .user,
                validityDuration: 7200,
                criticalOptions: nil,
                extensions: [
                    "permit-X11-forwarding",
                    "permit-agent-forwarding",
                    "permit-port-forwarding",
                    "permit-pty",
                    "permit-user-rc"
                ]
            )
        }
    }
    
    /// Generate a test certificate with configuration
    static func generateTestCertificate(config: TestCertificateConfig, caKeyPair: (privateKey: URL, publicKey: URL)) throws -> (privateKey: URL, publicKey: URL, certificate: URL) {
        // Generate user key pair
        let userKeyPair = try generateUserKeyPair(type: config.keyType, name: "user")
        
        // Generate certificate
        let certificatePath = try generateCertificate(
            userPublicKey: userKeyPair.publicKey,
            caPrivateKey: caKeyPair.privateKey,
            serial: config.serial,
            keyID: config.keyID,
            principals: config.principals,
            certType: config.certType,
            validityDuration: config.validityDuration,
            criticalOptions: config.criticalOptions,
            extensions: config.extensions
        )
        
        return (userKeyPair.privateKey, userKeyPair.publicKey, certificatePath)
    }
}