import Crypto
import Foundation
import NIO
@testable import NIOSSH
import XCTest
@testable import Citadel

final class RSACertificateIntegrationTests: XCTestCase {
    func testCertificateLoaderDetectsRSAComponentsWithoutRegisteringThem() {
        let ed25519CertificateType = "ssh-ed25519-cert-v01@openssh.com"

        XCTAssertFalse(
            NIOSSHCertificateLoader.requiresRSARegistration(
                for: syntheticCertificate(
                    keyType: ed25519CertificateType,
                    signatureAlgorithm: "ssh-ed25519"
                )
            )
        )

        for signatureAlgorithm in ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"] {
            XCTAssertTrue(
                NIOSSHCertificateLoader.requiresRSARegistration(
                    for: syntheticCertificate(
                        keyType: ed25519CertificateType,
                        signatureAlgorithm: signatureAlgorithm
                    )
                ),
                "an RSA CA signature requires the custom RSA parser"
            )
        }

        XCTAssertTrue(
            NIOSSHCertificateLoader.requiresRSARegistration(
                for: syntheticCertificate(
                    keyType: "ssh-rsa-cert-v01@openssh.com",
                    signatureAlgorithm: "ssh-ed25519"
                )
            ),
            "an RSA subject key requires the custom RSA parser"
        )

        XCTAssertFalse(NIOSSHCertificateLoader.requiresRSARegistration(for: "not-a-key"))
    }

    func testCertificateLoaderDoesNotTreatRSAAuthenticationNamesAsCertificateTypes() {
        for keyType in [
            "ssh-rsa",
            "rsa-sha2-256-cert-v01@openssh.com",
            "rsa-sha2-512-cert-v01@openssh.com",
        ] {
            XCTAssertFalse(
                NIOSSHCertificateLoader.requiresRSARegistration(
                    for: syntheticCertificate(
                        keyType: keyType,
                        signatureAlgorithm: "ssh-ed25519"
                    )
                ),
                "\(keyType) is not an RSA certificate blob identifier"
            )
        }
    }

    func testCertificateLoaderDoesNotAssumeOpaqueCertificateFormatsRequireRSA() {
        let customCertificate = syntheticCertificate(
            keyType: "custom-key-cert-v01@openssh.com",
            signatureAlgorithm: "rsa-sha2-256"
        )

        XCTAssertFalse(
            NIOSSHCertificateLoader.requiresRSARegistration(for: customCertificate),
            "the structural preflight cannot inspect caller-registered certificate formats"
        )
    }

    func testCertificateLoaderRejectsPlainRSAKeyConsistently() {
        let keyType = "ssh-rsa"
        var publicKey = ByteBufferAllocator().buffer(capacity: 280)
        publicKey.writeSSHString(keyType)
        publicKey.writeSSHString(Data([0x01, 0x00, 0x01]))
        publicKey.writeSSHString(Data(repeating: 0x11, count: 256))
        let openSSHString = "\(keyType) \(Data(publicKey.readableBytesView).base64EncodedString())"

        assertNotACertificateError(for: openSSHString)
        SSHAlgorithms.registerRSA()
        assertNotACertificateError(for: openSSHString)
    }

    func testCertificateLoaderRejectsTruncatedRSACertificatePreflight() {
        let keyType = "ssh-rsa-cert-v01@openssh.com"
        var certificate = ByteBufferAllocator().buffer(capacity: 64)
        certificate.writeSSHString(keyType)
        certificate.writeSSHString(Data([0xaa, 0xbb, 0xcc])) // nonce
        certificate.writeSSHString(Data([0x01, 0x00, 0x01])) // exponent; modulus is missing

        let openSSHString = "\(keyType) \(Data(certificate.readableBytesView).base64EncodedString())"
        XCTAssertFalse(NIOSSHCertificateLoader.requiresRSARegistration(for: openSSHString))
    }

    #if os(macOS) || os(Linux)
    func testRSAConvenienceAPIsDoNotRegisterAHostKeyAlgorithm() throws {
        let probeEnvironmentKey = "CITADEL_RSA_REGISTRATION_ISOLATION_PROBE"
        guard ProcessInfo.processInfo.environment[probeEnvironmentKey] == "1" else {
            try runIsolatedTestProcess(
                "CitadelTests.RSACertificateIntegrationTests/testRSAConvenienceAPIsDoNotRegisterAHostKeyAlgorithm",
                environmentKey: probeEnvironmentKey
            )
            return
        }

        NIOSSHAlgorithms.unregisterAlgorithms()
        assertRSAHostKeyAlgorithmIsNotRegistered()

        let privateKey = Insecure.RSA.PrivateKey(bits: 2048)
        _ = SSHAuthenticationMethod.rsa(username: "testuser", privateKey: privateKey)
        _ = SSHAuthenticationMethod.rsaSha256(username: "testuser", privateKey: privateKey)
        _ = SSHAuthenticationMethod.rsaSha512(username: "testuser", privateKey: privateKey)
        assertRSAHostKeyAlgorithmIsNotRegistered()

        let ed25519PrivateKey = NIOSSHPrivateKey(ed25519Key: .init())
        let placeholderSignature = try ed25519PrivateKey.sign(
            digest: SHA256.hash(data: Data("rsa-registration-isolation".utf8))
        )
        let certificate = try NIOSSHCertifiedPublicKey(
            nonce: ByteBuffer(repeating: 0xa5, count: 32),
            serial: 1,
            type: .user,
            key: ed25519PrivateKey.publicKey,
            keyID: "rsa-registration-isolation",
            validPrincipals: ["testuser"],
            validAfter: 0,
            validBefore: .max,
            criticalOptions: [:],
            extensions: [:],
            signatureKey: ed25519PrivateKey.publicKey,
            signature: placeholderSignature
        )
        _ = try SSHAuthenticationMethod.rsaCertificate(
            username: "testuser",
            privateKey: privateKey,
            certificate: certificate
        )
        _ = try SSHAuthenticationMethod.rsaSha256Certificate(
            username: "testuser",
            privateKey: privateKey,
            certificate: certificate
        )
        _ = try SSHAuthenticationMethod.rsaSha512Certificate(
            username: "testuser",
            privateKey: privateKey,
            certificate: certificate
        )
        assertRSAHostKeyAlgorithmIsNotRegistered()

        let completeRSACertificate = syntheticCertificate(
            keyType: "ssh-rsa-cert-v01@openssh.com",
            signatureAlgorithm: "ssh-ed25519"
        )
        XCTAssertThrowsError(
            try NIOSSHCertificateLoader.loadFromOpenSSHString(completeRSACertificate)
        ) { error in
            guard case NIOSSHCertificateLoadingError.unsupportedCertificateType = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
        assertRSAHostKeyAlgorithmIsNotRegistered()

        XCTAssertThrowsError(
            try NIOSSHCertificateLoader.loadFromOpenSSHString(
                truncatedRSACertificateOpenSSHString()
            )
        )
        assertRSAHostKeyAlgorithmIsNotRegistered()
    }
    #endif

    func testLegacyRSACertificateAuthenticationRegistrationIsExplicitAndIdempotent() throws {
        let mapping = SSHAlgorithms.legacyRSACertificateAuthenticationAlgorithm
        XCTAssertEqual(mapping.name, "ssh-rsa")
        XCTAssertEqual(mapping.certificate?.publicKeyPrefix, "ssh-rsa-cert-v01@openssh.com")
        XCTAssertEqual(mapping.certificate?.name, "ssh-rsa-cert-v01@openssh.com")

        SSHAlgorithms.registerLegacyRSACertificateAuthentication()
        SSHAlgorithms.registerLegacyRSACertificateAuthentication()

        let privateKey = Insecure.RSA.PrivateKey(bits: 2048)
        XCTAssertEqual(
            privateKey.userAuthenticationAlgorithmIdentifier,
            "ssh-rsa",
            "the legacy registration must not change the key's upstream-compatible default"
        )

        let caPrivateKey = NIOSSHPrivateKey(ed25519Key: .init())
        let placeholderSignature = try caPrivateKey.sign(
            digest: SHA256.hash(data: Data("legacy-rsa-certificate-registration".utf8))
        )
        let certificate = try NIOSSHCertifiedPublicKey(
            nonce: ByteBuffer(repeating: 0xa5, count: 32),
            serial: 1,
            type: .user,
            key: NIOSSHPrivateKey(custom: privateKey).publicKey,
            keyID: "legacy-rsa-certificate-registration",
            validPrincipals: ["testuser"],
            validAfter: 0,
            validBefore: .max,
            criticalOptions: [:],
            extensions: [:],
            signatureKey: caPrivateKey.publicKey,
            signature: placeholderSignature
        )
        let certifiedPublicKey = NIOSSHPublicKey(certificate)
        let selectedAlgorithm = try XCTUnwrap(
            certifiedPublicKey.userAuthenticationAlgorithm(
                forAlgorithmIdentifier: mapping.name
            )
        )
        let parsedAlgorithm = try XCTUnwrap(
            certifiedPublicKey.userAuthenticationAlgorithm(
                named: try XCTUnwrap(mapping.certificate?.name)
            )
        )

        XCTAssertEqual(selectedAlgorithm.name, mapping.certificate?.name)
        XCTAssertEqual(selectedAlgorithm.signaturePrefix, Insecure.RSA.Signature.signaturePrefix)
        XCTAssertEqual(parsedAlgorithm.name, mapping.certificate?.name)
        XCTAssertEqual(parsedAlgorithm.signaturePrefix, Insecure.RSA.Signature.signaturePrefix)
    }

    func testRSAAuthenticationFactoriesBindIdentifiersAndSignaturesWithoutMutatingKey() throws {
        SSHAlgorithms.registerLegacyRSACertificateAuthentication()
        let privateKey = Insecure.RSA.PrivateKey(bits: 2048)
        let publicKey = try XCTUnwrap(privateKey.publicKey as? Insecure.RSA.PublicKey)
        let message = Data("citadel-rsa-authentication-factory".utf8)
        let certificate = try makeUserCertificate(for: privateKey)

        XCTAssertEqual(privateKey.userAuthenticationAlgorithmIdentifier, "ssh-rsa")

        try assertRSAAuthentication(
            SSHAuthenticationMethod.rsa(username: "testuser", privateKey: privateKey),
            identifier: "ssh-rsa",
            authenticationName: "ssh-rsa",
            signaturePrefix: "ssh-rsa",
            publicKey: publicKey,
            message: message
        )
        try assertRSAAuthentication(
            SSHAuthenticationMethod.rsaSha256(username: "testuser", privateKey: privateKey),
            identifier: "rsa-sha2-256",
            authenticationName: "rsa-sha2-256",
            signaturePrefix: "rsa-sha2-256",
            publicKey: publicKey,
            message: message
        )
        try assertRSAAuthentication(
            SSHAuthenticationMethod.rsaSha512(username: "testuser", privateKey: privateKey),
            identifier: "rsa-sha2-512",
            authenticationName: "rsa-sha2-512",
            signaturePrefix: "rsa-sha2-512",
            publicKey: publicKey,
            message: message
        )
        try assertRSAAuthentication(
            SSHAuthenticationMethod.rsaCertificate(
                username: "testuser",
                privateKey: privateKey,
                certificate: certificate
            ),
            identifier: "ssh-rsa",
            authenticationName: "ssh-rsa-cert-v01@openssh.com",
            signaturePrefix: "ssh-rsa",
            publicKey: publicKey,
            message: message
        )
        try assertRSAAuthentication(
            SSHAuthenticationMethod.rsaSha256Certificate(
                username: "testuser",
                privateKey: privateKey,
                certificate: certificate
            ),
            identifier: "rsa-sha2-256",
            authenticationName: "rsa-sha2-256-cert-v01@openssh.com",
            signaturePrefix: "rsa-sha2-256",
            publicKey: publicKey,
            message: message
        )
        try assertRSAAuthentication(
            SSHAuthenticationMethod.rsaSha512Certificate(
                username: "testuser",
                privateKey: privateKey,
                certificate: certificate
            ),
            identifier: "rsa-sha2-512",
            authenticationName: "rsa-sha2-512-cert-v01@openssh.com",
            signaturePrefix: "rsa-sha2-512",
            publicKey: publicKey,
            message: message
        )

        XCTAssertEqual(
            privateKey.userAuthenticationAlgorithmIdentifier,
            "ssh-rsa",
            "constructing algorithm-specific offers must not mutate the reusable key"
        )
    }

    func testRSAAuthenticationUsesDistinctWireIdentifiersAndBodyOnlySignatures() throws {
        let privateKey = Insecure.RSA.PrivateKey(bits: 2048)
        let publicKey = try XCTUnwrap(privateKey.publicKey as? Insecure.RSA.PublicKey)
        let sha256Mapping = SSHAlgorithms.rsaSha256AuthenticationAlgorithm
        let sha512Mapping = SSHAlgorithms.rsaSha512AuthenticationAlgorithm

        XCTAssertEqual(Insecure.RSA.PublicKey.publicKeyPrefix, "ssh-rsa")
        XCTAssertEqual(privateKey.userAuthenticationAlgorithmIdentifier, "ssh-rsa")
        XCTAssertEqual(sha256Mapping.name, "rsa-sha2-256")
        XCTAssertEqual(sha256Mapping.certificate?.publicKeyPrefix, "ssh-rsa-cert-v01@openssh.com")
        XCTAssertEqual(
            sha256Mapping.certificate?.name,
            "rsa-sha2-256-cert-v01@openssh.com"
        )
        XCTAssertEqual(sha512Mapping.name, "rsa-sha2-512")
        XCTAssertEqual(sha512Mapping.certificate?.publicKeyPrefix, "ssh-rsa-cert-v01@openssh.com")
        XCTAssertEqual(
            sha512Mapping.certificate?.name,
            "rsa-sha2-512-cert-v01@openssh.com"
        )

        let message = Data("citadel-rsa-certificate-authentication".utf8)
        let legacySignature = try XCTUnwrap(
            try (privateKey as NIOSSHPrivateKeyProtocol).signature(for: message) as? Insecure.RSA.Signature
        )
        XCTAssertEqual(Insecure.RSA.Signature.signaturePrefix, "ssh-rsa")
        XCTAssertTrue(publicKey.isValidSignature(legacySignature, for: message))

        let defaultAuthenticationSignature = try XCTUnwrap(
            try privateKey.userAuthenticationSignature(for: message)
                as? Insecure.RSA.Signature
        )
        XCTAssertTrue(publicKey.isValidSignature(defaultAuthenticationSignature, for: message))

        let sha256AuthenticationKey = RSAAuthenticationPrivateKey(
            privateKey: privateKey,
            algorithm: .sha256
        )
        let signature = try XCTUnwrap(
            try sha256AuthenticationKey.userAuthenticationSignature(for: message)
                as? Insecure.RSA.Sha256Signature
        )
        XCTAssertEqual(Insecure.RSA.Sha256Signature.signaturePrefix, "rsa-sha2-256")
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message))

        var signatureBody = ByteBufferAllocator().buffer(capacity: signature.rawRepresentation.count + 4)
        XCTAssertEqual(
            signature.write(to: &signatureBody),
            signature.rawRepresentation.count + MemoryLayout<UInt32>.size
        )
        XCTAssertEqual(try readSSHField(from: &signatureBody), signature.rawRepresentation)
        XCTAssertEqual(signatureBody.readableBytes, 0, "the signature prefix must be framed by NIOSSH exactly once")

        var encodedBody = ByteBufferAllocator().buffer(capacity: signature.rawRepresentation.count + 4)
        encodedBody.writeInteger(UInt32(signature.rawRepresentation.count))
        encodedBody.writeBytes(signature.rawRepresentation)
        let decodedSignature = try Insecure.RSA.Sha256Signature.read(from: &encodedBody)
        XCTAssertEqual(decodedSignature.rawRepresentation, signature.rawRepresentation)
        XCTAssertEqual(encodedBody.readableBytes, 0)

        var publicKeyBody = ByteBufferAllocator().buffer(capacity: 512)
        let publicKeyBodyLength: Int = publicKey.write(to: &publicKeyBody)
        XCTAssertEqual(publicKeyBodyLength, publicKeyBody.readableBytes)
        XCTAssertEqual(try readSSHField(from: &publicKeyBody), Data([0x01, 0x00, 0x01]))
        XCTAssertGreaterThan(try readSSHField(from: &publicKeyBody).count, 200)
        XCTAssertEqual(publicKeyBody.readableBytes, 0, "the RSA key body must contain e and n directly")
    }

    #if os(macOS)
    func testLoadsAndValidatesEd25519CertificateSignedByRSACAUsingSHA512() throws {
        let sshKeygen = "/usr/bin/ssh-keygen"
        guard FileManager.default.isExecutableFile(atPath: sshKeygen) else {
            throw XCTSkip("OpenSSH interoperability tool is unavailable: \(sshKeygen)")
        }

        let temporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("citadel-rsa-ca-cert-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: temporaryDirectory,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: temporaryDirectory) }

        let caKeyPath = temporaryDirectory.appendingPathComponent("ca_key")
        let userKeyPath = temporaryDirectory.appendingPathComponent("user_key")
        try run(sshKeygen, ["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", caKeyPath.path])
        try run(sshKeygen, ["-q", "-t", "ed25519", "-N", "", "-f", userKeyPath.path])
        try run(
            sshKeygen,
            [
                "-q", "-s", caKeyPath.path,
                "-I", "citadel-rsa-ca-cert",
                "-n", "testuser",
                "-V", "-1m:+10m",
                "\(userKeyPath.path).pub",
            ]
        )

        let certificatePath = "\(userKeyPath.path)-cert.pub"
        let certificateText = try String(contentsOfFile: certificatePath, encoding: .utf8)
        XCTAssertTrue(NIOSSHCertificateLoader.requiresRSARegistration(for: certificateText))
        XCTAssertEqual(
            try certificateSignatureAlgorithm(fromOpenSSH: certificateText),
            "rsa-sha2-512"
        )

        SSHAlgorithms.registerRSA()
        let certificate = try NIOSSHCertificateLoader.loadFromOpenSSHFile(at: certificatePath)
        let caPublicKeyText = try String(contentsOfFile: "\(caKeyPath.path).pub", encoding: .utf8)
        let caPublicKey = try NIOSSHPublicKey(openSSHPublicKey: caPublicKeyText)
        let criticalOptions = try certificate.validate(
            principal: "testuser",
            type: .user,
            allowedAuthoritySigningKeys: [caPublicKey]
        )
        XCTAssertTrue(criticalOptions.isEmpty)
    }

    func testAuthenticatesToRestrictedOpenSSHThroughCitadelPublicAPI() async throws {
        let sshKeygen = "/usr/bin/ssh-keygen"
        let sshd = "/usr/sbin/sshd"
        let netcat = "/usr/bin/nc"
        for executable in [sshKeygen, sshd, netcat]
        where !FileManager.default.isExecutableFile(atPath: executable) {
            throw XCTSkip("OpenSSH interoperability tool is unavailable: \(executable)")
        }

        let temporaryDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("citadel-rsa-cert-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: temporaryDirectory,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: temporaryDirectory) }

        let hostKeyPath = temporaryDirectory.appendingPathComponent("host_key")
        let caKeyPath = temporaryDirectory.appendingPathComponent("ca_key")
        let userKeyPath = temporaryDirectory.appendingPathComponent("user_key")
        let username = NSUserName()

        try run(sshKeygen, ["-q", "-t", "ed25519", "-N", "", "-f", hostKeyPath.path])
        try run(sshKeygen, ["-q", "-t", "ed25519", "-N", "", "-f", caKeyPath.path])
        try run(sshKeygen, ["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f", userKeyPath.path])
        try run(
            sshKeygen,
            [
                "-q", "-s", caKeyPath.path,
                "-I", "citadel-rsa-cert",
                "-n", username,
                "-V", "-1m:+10m",
                "\(userKeyPath.path).pub",
            ]
        )

        let certificatePath = "\(userKeyPath.path)-cert.pub"
        let certificateText = try String(contentsOfFile: certificatePath, encoding: .utf8)
        let certificateParts = certificateText.split(
            separator: " ",
            maxSplits: 2,
            omittingEmptySubsequences: true
        )
        XCTAssertEqual(certificateParts.first, "ssh-rsa-cert-v01@openssh.com")
        let certificateBlob = try XCTUnwrap(Data(base64Encoded: String(certificateParts[1])))
        var certificateBuffer = ByteBufferAllocator().buffer(capacity: certificateBlob.count)
        certificateBuffer.writeBytes(certificateBlob)
        XCTAssertEqual(
            String(decoding: try readSSHField(from: &certificateBuffer), as: UTF8.self),
            "ssh-rsa-cert-v01@openssh.com"
        )
        _ = try readSSHField(from: &certificateBuffer)
        XCTAssertEqual(try readSSHField(from: &certificateBuffer), Data([0x01, 0x00, 0x01]))
        XCTAssertGreaterThan(try readSSHField(from: &certificateBuffer).count, 200)

        let privateKey = try Insecure.RSA.PrivateKey(sshRsa: Data(contentsOf: userKeyPath))
        SSHAlgorithms.registerRSA()
        let certificate = try NIOSSHCertificateLoader.loadFromOpenSSHFile(at: certificatePath)
        let authentication = try SSHAuthenticationMethod.rsaSha256Certificate(
            username: username,
            privateKey: privateKey,
            certificate: certificate
        )

        let group = MultiThreadedEventLoopGroup.singleton
        let port = try unusedLoopbackPort(group: group)

        let daemonLog = temporaryDirectory.appendingPathComponent("sshd.log")
        XCTAssertTrue(FileManager.default.createFile(atPath: daemonLog.path, contents: nil))
        let daemonLogHandle = try FileHandle(forWritingTo: daemonLog)
        let daemon = Process()
        daemon.executableURL = URL(fileURLWithPath: sshd)
        daemon.arguments = [
            "-D", "-e", "-f", "/dev/null",
            "-p", String(port),
            "-h", hostKeyPath.path,
            "-o", "ListenAddress=127.0.0.1",
            "-o", "PidFile=\(temporaryDirectory.appendingPathComponent("sshd.pid").path)",
            "-o", "AuthorizedKeysFile=none",
            "-o", "TrustedUserCAKeys=\(caKeyPath.path).pub",
            "-o", "StrictModes=no",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "UsePAM=no",
            "-o", "PubkeyAuthentication=yes",
            "-o", "PubkeyAcceptedAlgorithms=rsa-sha2-256-cert-v01@openssh.com",
            "-o", "CASignatureAlgorithms=ssh-ed25519",
        ]
        daemon.standardOutput = daemonLogHandle
        daemon.standardError = daemonLogHandle
        try daemon.run()
        defer {
            if daemon.isRunning {
                daemon.terminate()
            }
            daemon.waitUntilExit()
            try? daemonLogHandle.close()
        }

        guard waitUntilListening(netcat: netcat, port: port, daemon: daemon) else {
            if daemon.isRunning {
                daemon.terminate()
                daemon.waitUntilExit()
            }
            try? daemonLogHandle.synchronize()
            return XCTFail(
                "OpenSSH daemon did not start: \(try String(contentsOf: daemonLog, encoding: .utf8))"
            )
        }

        do {
            let client = try await SSHClient.connect(
                host: "127.0.0.1",
                port: port,
                authenticationMethod: authentication,
                hostKeyValidator: .acceptAnything(),
                reconnect: .never,
                group: group,
                connectTimeout: .seconds(10)
            )
            XCTAssertTrue(client.isConnected)
            try await client.close()
        } catch {
            try? daemonLogHandle.synchronize()
            XCTFail(
                "Citadel RSA certificate authentication failed: \(error)\n"
                    + (try String(contentsOf: daemonLog, encoding: .utf8))
            )
            throw error
        }
    }
    #endif

    private func readSSHField(from buffer: inout ByteBuffer) throws -> Data {
        guard let length = buffer.readInteger(as: UInt32.self),
              let bytes = buffer.readBytes(length: Int(length)) else {
            throw RSAInteropTestError.incompleteSSHField
        }
        return Data(bytes)
    }

    private func assertNotACertificateError(
        for openSSHString: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try NIOSSHCertificateLoader.loadFromOpenSSHString(openSSHString),
            file: file,
            line: line
        ) { error in
            guard let loadingError = error as? NIOSSHCertificateLoadingError else {
                return XCTFail("Unexpected error: \(error)", file: file, line: line)
            }

            guard case .notACertificate = loadingError else {
                return XCTFail("Unexpected loading error: \(loadingError)", file: file, line: line)
            }
        }
    }

    private func assertRSAHostKeyAlgorithmIsNotRegistered(
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertFalse(
            SSHKeyExchangeStateMachine.supportedServerHostKeyAlgorithms.contains { $0 == "ssh-rsa" },
            "RSA user-authentication setup must not affect host-key negotiation",
            file: file,
            line: line
        )
    }

    private func assertRSAAuthentication(
        _ authenticationMethod: SSHAuthenticationMethod,
        identifier expectedIdentifier: String,
        authenticationName expectedAuthenticationName: String,
        signaturePrefix expectedSignaturePrefix: String,
        publicKey: Insecure.RSA.PublicKey,
        message: Data,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let privateKeyOffer = try rsaAuthenticationOffer(from: authenticationMethod)
        guard case .custom(let authenticationKey) = privateKeyOffer.privateKey.backingKey else {
            throw RSAInteropTestError.unexpectedPrivateKeyType
        }
        XCTAssertEqual(
            authenticationKey.userAuthenticationAlgorithmIdentifier,
            expectedIdentifier,
            file: file,
            line: line
        )

        let resolvedAlgorithm = try XCTUnwrap(
            privateKeyOffer.publicKey.userAuthenticationAlgorithm(
                forAlgorithmIdentifier: expectedIdentifier
            ),
            "Expected a registered mapping for \(expectedIdentifier)",
            file: file,
            line: line
        )
        XCTAssertEqual(resolvedAlgorithm.name, expectedAuthenticationName, file: file, line: line)
        XCTAssertEqual(
            resolvedAlgorithm.signaturePrefix,
            expectedSignaturePrefix,
            file: file,
            line: line
        )

        let signature = try authenticationKey.userAuthenticationSignature(for: message)
        XCTAssertEqual(signature.signaturePrefix, expectedSignaturePrefix, file: file, line: line)
        XCTAssertTrue(publicKey.isValidSignature(signature, for: message), file: file, line: line)
    }

    private func rsaAuthenticationOffer(
        from authenticationMethod: SSHAuthenticationMethod
    ) throws -> NIOSSHUserAuthenticationOffer.Offer.PrivateKey {
        let promise = MultiThreadedEventLoopGroup.singleton.next().makePromise(
            of: NIOSSHUserAuthenticationOffer?.self
        )
        authenticationMethod.nextAuthenticationType(
            availableMethods: .publicKey,
            nextChallengePromise: promise
        )

        guard let offer = try promise.futureResult.wait() else {
            throw RSAInteropTestError.missingAuthenticationOffer
        }
        guard case .privateKey(let privateKeyOffer) = offer.offer else {
            throw RSAInteropTestError.unexpectedAuthenticationOffer
        }
        return privateKeyOffer
    }

    private func makeUserCertificate(
        for privateKey: Insecure.RSA.PrivateKey
    ) throws -> NIOSSHCertifiedPublicKey {
        let caPrivateKey = NIOSSHPrivateKey(ed25519Key: .init())
        let placeholderSignature = try caPrivateKey.sign(
            digest: SHA256.hash(data: Data("rsa-authentication-factory-certificate".utf8))
        )
        return try NIOSSHCertifiedPublicKey(
            nonce: ByteBuffer(repeating: 0xa5, count: 32),
            serial: 1,
            type: .user,
            key: NIOSSHPrivateKey(custom: privateKey).publicKey,
            keyID: "rsa-authentication-factory",
            validPrincipals: ["testuser"],
            validAfter: 0,
            validBefore: .max,
            criticalOptions: [:],
            extensions: [:],
            signatureKey: caPrivateKey.publicKey,
            signature: placeholderSignature
        )
    }

    private func truncatedRSACertificateOpenSSHString() -> String {
        let keyType = "ssh-rsa-cert-v01@openssh.com"
        var certificate = ByteBufferAllocator().buffer(capacity: 64)
        certificate.writeSSHString(keyType)
        certificate.writeSSHString(Data([0xaa, 0xbb, 0xcc]))
        certificate.writeSSHString(Data([0x01, 0x00, 0x01]))
        return "\(keyType) \(Data(certificate.readableBytesView).base64EncodedString())"
    }

    #if os(macOS) || os(Linux)
    private func runIsolatedTestProcess(
        _ testSelector: String,
        environmentKey: String
    ) throws {
        let process = Process()
        #if os(macOS)
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        process.arguments = [
            "xctest",
            "-XCTest",
            testSelector,
            Bundle(for: RSACertificateIntegrationTests.self).bundleURL.path,
        ]
        #elseif os(Linux)
        process.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        process.arguments = [testSelector]
        #endif

        var environment = ProcessInfo.processInfo.environment
        environment[environmentKey] = "1"
        process.environment = environment

        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        try process.run()
        process.waitUntilExit()

        let diagnostics = String(
            decoding: output.fileHandleForReading.readDataToEndOfFile(),
            as: UTF8.self
        )
        XCTAssertEqual(
            process.terminationStatus,
            0,
            "Isolated registry test failed:\n\(diagnostics)"
        )
    }
    #endif

    private func syntheticCertificate(keyType: String, signatureAlgorithm: String) -> String {
        var signature = ByteBufferAllocator().buffer(capacity: 64)
        signature.writeSSHString(signatureAlgorithm)
        signature.writeSSHString(Data([0x01, 0x02, 0x03]))

        var certificate = ByteBufferAllocator().buffer(capacity: 128)
        certificate.writeSSHString(keyType)
        certificate.writeSSHString(Data([0xaa, 0xbb, 0xcc])) // nonce
        if keyType == "ssh-rsa-cert-v01@openssh.com" {
            certificate.writeSSHString(Data([0x01, 0x00, 0x01])) // public exponent
            certificate.writeSSHString(Data(repeating: 0x11, count: 256)) // modulus
        } else if keyType == "ssh-ed25519-cert-v01@openssh.com" {
            certificate.writeSSHString(Data(repeating: 0x11, count: 32))
        } else if keyType.hasPrefix("ecdsa-sha2-") {
            certificate.writeSSHString("nistp256")
            certificate.writeSSHString(Data([0x04, 0x01]))
        }
        certificate.writeInteger(UInt64(1))
        certificate.writeInteger(UInt32(1))
        certificate.writeSSHString(Data("test-certificate".utf8))
        certificate.writeSSHString(Data())
        certificate.writeInteger(UInt64(0))
        certificate.writeInteger(UInt64.max)
        certificate.writeSSHString(Data())
        certificate.writeSSHString(Data())
        certificate.writeSSHString(Data())
        certificate.writeSSHString(Data())
        certificate.writeSSHString(Data(signature.readableBytesView))

        return "\(keyType) \(Data(certificate.readableBytesView).base64EncodedString())"
    }

    private func certificateSignatureAlgorithm(fromOpenSSH certificateText: String) throws -> String {
        let certificateParts = certificateText.split(
            separator: " ",
            maxSplits: 2,
            omittingEmptySubsequences: true
        )
        let encodedCertificate = try XCTUnwrap(certificateParts.dropFirst().first)
        let certificateBlob = try XCTUnwrap(Data(base64Encoded: String(encodedCertificate)))
        var certificateBuffer = ByteBufferAllocator().buffer(capacity: certificateBlob.count)
        certificateBuffer.writeBytes(certificateBlob)

        let keyType = String(decoding: try readSSHField(from: &certificateBuffer), as: UTF8.self)
        _ = try readSSHField(from: &certificateBuffer) // nonce
        switch keyType {
        case "ssh-ed25519-cert-v01@openssh.com":
            _ = try readSSHField(from: &certificateBuffer)
        case "ssh-rsa-cert-v01@openssh.com":
            _ = try readSSHField(from: &certificateBuffer) // exponent
            _ = try readSSHField(from: &certificateBuffer) // modulus
        case "ecdsa-sha2-nistp256-cert-v01@openssh.com",
             "ecdsa-sha2-nistp384-cert-v01@openssh.com",
             "ecdsa-sha2-nistp521-cert-v01@openssh.com":
            _ = try readSSHField(from: &certificateBuffer) // curve name
            _ = try readSSHField(from: &certificateBuffer) // public key
        default:
            throw RSAInteropTestError.unexpectedCertificateKeyType(keyType)
        }
        _ = try XCTUnwrap(certificateBuffer.readInteger(as: UInt64.self))
        _ = try XCTUnwrap(certificateBuffer.readInteger(as: UInt32.self))
        _ = try readSSHField(from: &certificateBuffer)
        _ = try readSSHField(from: &certificateBuffer)
        _ = try XCTUnwrap(certificateBuffer.readInteger(as: UInt64.self))
        _ = try XCTUnwrap(certificateBuffer.readInteger(as: UInt64.self))
        for _ in 0..<4 {
            _ = try readSSHField(from: &certificateBuffer)
        }

        let signatureBlob = try readSSHField(from: &certificateBuffer)
        XCTAssertEqual(certificateBuffer.readableBytes, 0)
        var signatureBuffer = ByteBufferAllocator().buffer(capacity: signatureBlob.count)
        signatureBuffer.writeBytes(signatureBlob)
        let signatureAlgorithm = try readSSHField(from: &signatureBuffer)
        _ = try readSSHField(from: &signatureBuffer)
        XCTAssertEqual(signatureBuffer.readableBytes, 0)
        return String(decoding: signatureAlgorithm, as: UTF8.self)
    }

    #if os(macOS)
    private func unusedLoopbackPort(group: EventLoopGroup) throws -> Int {
        let channel = try ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeSucceededVoidFuture()
            }
            .bind(host: "127.0.0.1", port: 0)
            .wait()
        defer { try? channel.close().wait() }
        return try XCTUnwrap(channel.localAddress?.port)
    }

    private func run(_ executable: String, _ arguments: [String]) throws {
        let process = Process()
        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = outputPipe
        process.standardError = errorPipe
        try process.run()
        process.waitUntilExit()
        _ = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0 else {
            throw RSAInteropTestError.processFailed(
                executable,
                process.terminationStatus,
                String(decoding: errorData, as: UTF8.self)
            )
        }
    }

    private func waitUntilListening(netcat: String, port: Int, daemon: Process) -> Bool {
        for _ in 0..<100 {
            guard daemon.isRunning else {
                return false
            }
            let probe = Process()
            probe.executableURL = URL(fileURLWithPath: netcat)
            probe.arguments = ["-z", "127.0.0.1", String(port)]
            probe.standardOutput = FileHandle.nullDevice
            probe.standardError = FileHandle.nullDevice
            try? probe.run()
            probe.waitUntilExit()
            if probe.terminationStatus == 0 {
                return true
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return false
    }
    #endif
}

private enum RSAInteropTestError: Error {
    case incompleteSSHField
    case missingAuthenticationOffer
    case processFailed(String, Int32, String)
    case unexpectedAuthenticationOffer
    case unexpectedCertificateKeyType(String)
    case unexpectedPrivateKeyType
}
