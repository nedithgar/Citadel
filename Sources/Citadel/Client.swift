import NIO
import Crypto
import Logging
import NIOSSH

extension SSHAlgorithms.Modification<NIOSSHTransportProtection.Type> {
    func apply(to configuration: inout [any NIOSSHTransportProtection.Type]) {
        switch self {
        case .add(let algorithms):
            configuration.append(contentsOf: algorithms)
            
            for algorithm: any NIOSSHTransportProtection.Type in algorithms {
                NIOSSHAlgorithms.register(transportProtectionScheme: algorithm)
            }
        case .replace(with: let algorithms):
            configuration = algorithms
            
            for algorithm in algorithms {
                NIOSSHAlgorithms.register(transportProtectionScheme: algorithm)
            }
        }
    }
}

extension SSHAlgorithms.Modification<NIOSSHKeyExchangeAlgorithmProtocol.Type> {
    func apply(to configuration: inout [any NIOSSHKeyExchangeAlgorithmProtocol.Type]) {
        switch self {
        case .add(let algorithms):
            configuration.append(contentsOf: algorithms)
            
            for algorithm in algorithms {
                NIOSSHAlgorithms.register(keyExchangeAlgorithm: algorithm)
            }
        case .replace(with: let algorithms):
            configuration = algorithms
            
            for algorithm in algorithms {
                NIOSSHAlgorithms.register(keyExchangeAlgorithm: algorithm)
            }
        }
    }
}

extension SSHAlgorithms.Modification<(NIOSSHPublicKeyProtocol.Type, NIOSSHSignatureProtocol.Type)>{
    func register() {
        switch self {
        case .add(let algorithms):
            for (publicKey, signature) in algorithms {
                NIOSSHAlgorithms.register(publicKey: publicKey, signature: signature)
            }
        case .replace(with: let algorithms):
            for (publicKey, signature) in algorithms {
                NIOSSHAlgorithms.register(publicKey: publicKey, signature: signature)
            }
        }
    }
}

public struct SSHAlgorithms: Sendable {
    static let rsaSha256AuthenticationAlgorithm = NIOSSHUserAuthenticationAlgorithm(
        name: "rsa-sha2-256",
        certificate: .init(
            publicKeyPrefix: "ssh-rsa-cert-v01@openssh.com",
            name: "rsa-sha2-256-cert-v01@openssh.com"
        )
    )

    static let rsaSha512AuthenticationAlgorithm = NIOSSHUserAuthenticationAlgorithm(
        name: "rsa-sha2-512",
        certificate: .init(
            publicKeyPrefix: "ssh-rsa-cert-v01@openssh.com",
            name: "rsa-sha2-512-cert-v01@openssh.com"
        )
    )

    static let legacyRSACertificateAuthenticationAlgorithm = NIOSSHUserAuthenticationAlgorithm(
        name: "ssh-rsa",
        certificate: .init(
            publicKeyPrefix: "ssh-rsa-cert-v01@openssh.com",
            name: "ssh-rsa-cert-v01@openssh.com"
        )
    )

    /// Registers Citadel's RSA key and signature support, including SHA-2 certificate mappings.
    ///
    /// Call this explicitly before loading RSA certificates, using Citadel's plain RSA or SHA-2 RSA
    /// certificate authentication methods without ``all``, constructing RSA certificates directly
    /// with NIOSSH, or configuring a server that needs RSA support without enabling ``all``
    /// algorithms. Registration is process-wide, cannot be undone, and also enables RSA host-key
    /// negotiation in NIOSSH.
    /// This does not enable legacy `ssh-rsa-cert-v01@openssh.com` user authentication; use
    /// ``registerLegacyRSACertificateAuthentication()`` only when compatibility requires it.
    public static func registerRSA() {
        NIOSSHAlgorithms.register(
            publicKey: Insecure.RSA.PublicKey.self,
            signature: Insecure.RSA.Signature.self
        )
        NIOSSHAlgorithms.register(
            publicKey: Insecure.RSA.PublicKey.self,
            signature: Insecure.RSA.Sha256Signature.self,
            userAuthenticationAlgorithm: rsaSha256AuthenticationAlgorithm
        )
        NIOSSHAlgorithms.register(
            publicKey: Insecure.RSA.PublicKey.self,
            signature: Insecure.RSA.Sha512Signature.self,
            userAuthenticationAlgorithm: rsaSha512AuthenticationAlgorithm
        )
    }

    /// Enables legacy `ssh-rsa-cert-v01@openssh.com` user authentication.
    ///
    /// This process-wide registration enables RSA certificate authentication signatures that use
    /// SHA-1. Prefer the SHA-2 mappings registered by ``registerRSA()`` whenever the peer supports
    /// them. Registration is idempotent, but cannot be undone for the lifetime of the process.
    ///
    /// Calling this method does not change the algorithm selected by an authentication method. It
    /// enables
    /// ``SSHAuthenticationMethod/rsaCertificate(username:privateKey:certificate:trustedCAs:clientAddress:validateCertificate:)``
    /// and servers that must accept the legacy RSA certificate authentication name.
    public static func registerLegacyRSACertificateAuthentication() {
        registerRSA()
        NIOSSHAlgorithms.register(
            publicKey: Insecure.RSA.PublicKey.self,
            signature: Insecure.RSA.Signature.self,
            userAuthenticationAlgorithm: legacyRSACertificateAuthenticationAlgorithm
        )
    }

    /// Represents a modification to a list of items.
    ///
    /// - replace: Replaces the existing list of items with the given list of items.
    /// - add: Adds the given list of items to the list of items.
    public enum Modification<T: Sendable>: Sendable {
        case replace(with: [T])
        case add([T])
    }
    
    /// The enabled TransportProtectionSchemes.
    public var transportProtectionSchemes: Modification<NIOSSHTransportProtection.Type>?
    
    /// The enabled KeyExchangeAlgorithms
    public var keyExchangeAlgorithms: Modification<NIOSSHKeyExchangeAlgorithmProtocol.Type>?

    public var publicKeyAlgorihtms: Modification<(NIOSSHPublicKeyProtocol.Type, NIOSSHSignatureProtocol.Type)>?

    private var enablesRSA = false
    private var enablesLegacyRSACertificateAuthentication = false

    func apply(to clientConfiguration: inout SSHClientConfiguration) {
        transportProtectionSchemes?.apply(to: &clientConfiguration.transportProtectionSchemes)
        keyExchangeAlgorithms?.apply(to: &clientConfiguration.keyExchangeAlgorithms)
        registerPublicKeyAlgorithms()
    }
    
    func apply(to serverConfiguration: inout SSHServerConfiguration) {
        transportProtectionSchemes?.apply(to: &serverConfiguration.transportProtectionSchemes)
        keyExchangeAlgorithms?.apply(to: &serverConfiguration.keyExchangeAlgorithms)
        registerPublicKeyAlgorithms()
    }

    private func registerPublicKeyAlgorithms() {
        publicKeyAlgorihtms?.register()
        if enablesLegacyRSACertificateAuthentication {
            Self.registerLegacyRSACertificateAuthentication()
        } else if enablesRSA {
            Self.registerRSA()
        }
    }
    
    public init() {}

    /// All compatibility algorithms implemented by Citadel.
    ///
    /// This includes legacy `ssh-rsa-cert-v01@openssh.com` authentication. Applying this value
    /// performs the same process-wide, one-way registration as
    /// ``registerLegacyRSACertificateAuthentication()``.
    public static let all: SSHAlgorithms = {
        var algorithms = SSHAlgorithms()

        algorithms.transportProtectionSchemes = .add([
            AES128CTR.self
        ])

        algorithms.keyExchangeAlgorithms = .add([
            DiffieHellmanGroup14Sha1.self,
            DiffieHellmanGroup14Sha256.self
        ])

        algorithms.enablesRSA = true
        algorithms.enablesLegacyRSACertificateAuthentication = true

        return algorithms
    }()
}

/// Represents an SSH connection.
public final class SSHClient {
    private(set) var session: SSHClientSession
    private var userInitiatedClose = false
    let authenticationMethod: () -> SSHAuthenticationMethod
    let hostKeyValidator: SSHHostKeyValidator
    internal var connectionSettings = SSHConnectionPoolSettings()
    private let algorithms: SSHAlgorithms
    private let protocolOptions: Set<SSHProtocolOption>
    private var onDisconnect: (@Sendable () -> ())?
    public let logger = Logger(label: "nl.orlandos.citadel.client")
    public var isConnected: Bool {
        session.channel.isActive
    }
    
    /// The event loop that this SSH connection is running on.
    public var eventLoop: EventLoop {
        session.channel.eventLoop
    }
    
    init(
        session: SSHClientSession,
        authenticationMethod: @escaping @autoclosure () -> SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption>
    ) {
        self.session = session
        self.authenticationMethod = authenticationMethod
        self.hostKeyValidator = hostKeyValidator
        self.algorithms = algorithms
        self.protocolOptions = protocolOptions
        
        onNewSession(session)
    }
    
    public func onDisconnect(perform onDisconnect: @escaping @Sendable () -> ()) {
        self.onDisconnect = onDisconnect
    }

    /// Connects to an SSH server.
    /// - settings: The settings to use for the connection.
    /// - Returns: An SSH client.
    public static func connect(
        to settings: SSHClientSettings
    ) async throws -> SSHClient {
        let session = try await SSHClientSession.connect(settings: settings)
        
        return SSHClient(
            session: session,
            authenticationMethod: settings.authenticationMethod(),
            hostKeyValidator: settings.hostKeyValidator,
            algorithms: settings.algorithms,
            protocolOptions: settings.protocolOptions
        )
    }

    /// Connects to an SSH server.
    /// - settings: The settings to use for the connection.
    /// - Returns: An SSH client.
    public static func connect(
        on channel: Channel,
        settings: SSHClientSettings
    ) async throws -> SSHClient {
        let inboundChannelHandler = SSHClientInboundChannelHandler()
        try await SSHClientSession.addHandlers(
            on: channel,
            inboundChannelHandler: inboundChannelHandler,
            settings: settings
        ).get()
        
        let sshHandler = try await channel.pipeline.handler(type: NIOSSHHandler.self).get()
        let handshakeHandler = try await channel.pipeline.handler(type: ClientHandshakeHandler.self).get()
        let session = try await handshakeHandler.authenticated.map {
            SSHClientSession(channel: channel, inboundChannelHandler: inboundChannelHandler, sshHandler: sshHandler)
        }.get()

        return SSHClient(
            session: session,
            authenticationMethod: settings.authenticationMethod(),
            hostKeyValidator: settings.hostKeyValidator,
            algorithms: settings.algorithms,
            protocolOptions: settings.protocolOptions
        )
    }

    public func jump(to settings: SSHClientSettings) async throws -> SSHClient {
        let originatorAddress = try SocketAddress(ipAddress: "fe80::1", port: 22)
        let inboundChannelHandler = SSHClientInboundChannelHandler()
        let channel = try await self.createDirectTCPIPChannel(
            using: SSHChannelType.DirectTCPIP(
                targetHost: settings.host,
                targetPort: settings.port,
                originatorAddress: originatorAddress
            )
        ) { channel in
            SSHClientSession.addHandlers(
                on: channel,
                inboundChannelHandler: inboundChannelHandler,
                settings: settings
            )
        }
        
        let sshHandler = try await channel.pipeline.handler(type: NIOSSHHandler.self).get()
        let handshakeHandler = try await channel.pipeline.handler(type: ClientHandshakeHandler.self).get()
        let session = try await handshakeHandler.authenticated.map {
            SSHClientSession(channel: channel, inboundChannelHandler: inboundChannelHandler, sshHandler: sshHandler)
        }.get()

        return SSHClient(
            session: session,
            authenticationMethod: settings.authenticationMethod(),
            hostKeyValidator: settings.hostKeyValidator,
            algorithms: settings.algorithms,
            protocolOptions: settings.protocolOptions
        )
    }
    
    /// Connects to an SSH server.
    /// - Parameters:
    ///  - channel: The channel to use for the connection.
    /// - authenticationMethod: The authentication method to use. See `SSHAuthenticationMethod` for more information.
    /// - hostKeyValidator: The host key validator to use. See `SSHHostKeyValidator` for more information.
    /// - algorithms: The algorithms to use. See `SSHAlgorithms` for more information.
    /// - protocolOptions: The protocol options to use. See `SSHProtocolOption` for more information.
    /// - Returns: An SSH client.
    public static func connect(
        on channel: Channel,
        authenticationMethod: @escaping @autoclosure () -> SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption> = []
    ) async throws -> SSHClient {
        let inboundChannelHandler = SSHClientInboundChannelHandler()
        try await SSHClientSession.addHandlers(
            on: channel,
            authenticationMethod: authenticationMethod(),
            inboundChannelHandler: inboundChannelHandler,
            hostKeyValidator: hostKeyValidator,
            protocolOptions: protocolOptions
        ).get()
        
        let sshHandler = try await channel.pipeline.handler(type: NIOSSHHandler.self).get()
        let session = SSHClientSession(channel: channel, inboundChannelHandler: inboundChannelHandler, sshHandler: sshHandler)
        
        return SSHClient(
            session: session,
            authenticationMethod: authenticationMethod(),
            hostKeyValidator: hostKeyValidator,
            algorithms: algorithms,
            protocolOptions: protocolOptions
        )
    }
    
    /// Connects to an SSH server.
    /// - Parameters:
    /// - host: The host to connect to.
    /// - port: The port to connect to. Defaults to 22.
    /// - authenticationMethod: The authentication method to use. See `SSHAuthenticationMethod` for more information.
    /// - hostKeyValidator: The host key validator to use. See `SSHHostKeyValidator` for more information.
    /// - reconnect: The reconnect mode to use. See `SSHReconnectMode` for more information.
    /// - algorithms: The algorithms to use. See `SSHAlgorithms` for more information.
    /// - protocolOptions: The protocol options to use. See `SSHProtocolOption` for more information.
    /// - group: The event loop group to use. Defaults to a single-threaded event loop group.
    /// - channelHandlers: Pass in an array of channel prehandlers that execute first. Default empty array
    /// - connectTimeout: Pass in the time before the connection times out. Default 30 seconds.
    /// - Returns: An SSH client.
    public static func connect(
        host: String,
        port: Int = 22,
        authenticationMethod: SSHAuthenticationMethod,
        hostKeyValidator: SSHHostKeyValidator,
        reconnect: SSHReconnectMode,
        algorithms: SSHAlgorithms = SSHAlgorithms(),
        protocolOptions: Set<SSHProtocolOption> = [],
        group: MultiThreadedEventLoopGroup = .singleton,
        channelHandlers: [ChannelHandler] = [],
        connectTimeout:TimeAmount = .seconds(30)
    ) async throws -> SSHClient {
        let session = try await SSHClientSession.connect(
            host: host,
            port: port,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator,
            algorithms: algorithms,
            protocolOptions: protocolOptions,
            group: group,
            channelHandlers: channelHandlers,
            connectTimeout: connectTimeout
        )
        
        let client = SSHClient(
            session: session,
            authenticationMethod: authenticationMethod,
            hostKeyValidator: hostKeyValidator,
            algorithms: algorithms,
            protocolOptions: protocolOptions
        )
        
        switch reconnect.mode {
        case .always:
            client.connectionSettings.reconnect = .always(to: host, port: port)
        case .once:
            client.connectionSettings.reconnect = .once(to: host, port: port)
        case .never:
            client.connectionSettings.reconnect = .never
        }
        
        return client
    }
    
    private func onNewSession(_ session: SSHClientSession) {
        session.channel.closeFuture.whenComplete { [weak self] _ in
            self?.onClose()
        }
    }
    
    private func onClose() {
        Task {
            self.onDisconnect?()
            
            switch connectionSettings.reconnect.mode {
            case .never:
                return
            case .once(let host, let port):
                _ = try? await self.recreateSession(host: host, port: port)
            case .always(let host, let port):
                func tryAgain() async throws {
                    do {
                        try await self.recreateSession(host: host, port: port)
                    } catch {
                        return try await tryAgain()
                    }
                }
                
                _ = try? await tryAgain()
            }
        }
    }
    
    private func recreateSession(host: String, port: Int) async throws {
        if userInitiatedClose {
            return
        }
        
        self.session = try await SSHClientSession.connect(
            host: host,
            port: port,
            authenticationMethod: self.authenticationMethod(),
            hostKeyValidator: self.hostKeyValidator,
            protocolOptions: protocolOptions,
            group: session.channel.eventLoop
        )
        
        onNewSession(session)
    }
    
    public func close() async throws {
        self.userInitiatedClose = true
        try await self.session.channel.close()
    }
}
