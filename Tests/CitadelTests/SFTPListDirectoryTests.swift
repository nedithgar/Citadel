import XCTest
@testable import Citadel
import NIO
import NIOSSH
import Logging

final class SFTPListDirectoryTests: XCTestCase {
    
    /// Test that listDirectory can handle more than 100 files
    func testListDirectoryWithMoreThan100Files() async throws {
        let logger = Logger(label: "sftp-test")
        
        // Create a mock SFTP delegate
        let mockDelegate = MockSFTPDelegate()
        
        // Setup server
        let authDelegate = AuthDelegate(supportedAuthenticationMethods: .password) { request, promise in
            switch request.request {
            case .password(.init(password: "test")) where request.username == "citadel":
                promise.succeed(.success)
            default:
                promise.succeed(.failure)
            }
        }
        
        let server = try await SSHServer.host(
            host: "localhost",
            port: 0, // Use any available port
            hostKeys: [.init(p521Key: .init())],
            authenticationDelegate: authDelegate
        )
        
        // Enable SFTP on the server
        server.enableSFTP(withDelegate: mockDelegate)
        
        let serverPort = try server.channel.localAddress?.port ?? 0
        XCTAssertNotEqual(serverPort, 0)
        
        // Connect client
        let client = try await SSHClient.connect(
            host: "localhost",
            port: serverPort,
            authenticationMethod: .passwordBased(username: "citadel", password: "test"),
            hostKeyValidator: .acceptAnything(),
            reconnect: .never
        )
        
        // Test with SFTP
        try await client.withSFTP { sftp in
            // Create a test directory with 150 files
            let testDirPath = "/test_many_files"
            mockDelegate.createTestDirectory(at: testDirPath, fileCount: 150)
            
            // List the directory
            let files = try await sftp.listDirectory(atPath: testDirPath)
            
            // Verify we get all 150 files plus . and .. entries
            XCTAssertEqual(files.count, 152, "Expected 152 files (150 + . and ..) but got \(files.count)")
            
            // Verify the files are numbered correctly (accounting for . and .. entries)
            let filenames = files.map { $0.filename }
            XCTAssertTrue(filenames.contains("."))
            XCTAssertTrue(filenames.contains(".."))
            
            for i in 0..<150 {
                let expectedFilename = "file_\(String(format: "%03d", i)).txt"
                XCTAssertTrue(filenames.contains(expectedFilename), "Missing file: \(expectedFilename)")
            }
        }
        
        // Cleanup
        try await client.close()
        try await server.close()
    }
}

// Mock SFTP Delegate for testing
class MockSFTPDelegate: SFTPDelegate {
    private var _virtualFileSystem: [String: [SFTPPathComponent]] = [:]
    
    var virtualFileSystem: [String: [SFTPPathComponent]] {
        get { _virtualFileSystem }
        set { _virtualFileSystem = newValue }
    }
    
    func createTestDirectory(at path: String, fileCount: Int) {
        var files: [SFTPPathComponent] = []
        
        // Add . and .. entries
        var dirAttributes = SFTPFileAttributes()
        dirAttributes.size = 68
        dirAttributes.permissions = 0o755
        dirAttributes.uidgid = SFTPFileAttributes.UserGroupId(userId: 1000, groupId: 1000)
        
        files.append(SFTPPathComponent(
            filename: ".",
            longname: "drwxr-xr-x    2 user     group           68 Jan  1 00:00 .",
            attributes: dirAttributes
        ))
        
        files.append(SFTPPathComponent(
            filename: "..",
            longname: "drwxr-xr-x    2 user     group           68 Jan  1 00:00 ..",
            attributes: dirAttributes
        ))
        
        // Add test files
        for i in 0..<fileCount {
            let filename = "file_\(String(format: "%03d", i)).txt"
            var fileAttributes = SFTPFileAttributes()
            fileAttributes.size = 1024
            fileAttributes.permissions = 0o644
            fileAttributes.uidgid = SFTPFileAttributes.UserGroupId(userId: 1000, groupId: 1000)
            
            files.append(SFTPPathComponent(
                filename: filename,
                longname: "-rw-r--r--    1 user     group         1024 Jan  1 00:00 \(filename)",
                attributes: fileAttributes
            ))
        }
        
        virtualFileSystem[path] = files
    }
    
    func openDirectory(atPath path: String, context: SSHContext) async throws -> SFTPDirectoryHandle {
        return MockDirectoryHandle(path: path, delegate: self)
    }
    
    func realPath(for path: String, context: SSHContext) async throws -> [SFTPPathComponent] {
        return [SFTPPathComponent(
            filename: path,
            longname: path,
            attributes: .none
        )]
    }
    
    // Implement other required methods with stub implementations
    func openFile(_ filePath: String, withAttributes attributes: SFTPFileAttributes, flags: SFTPOpenFileFlags, context: SSHContext) async throws -> SFTPFileHandle {
        throw SFTPError.unknownMessage
    }
    
    func createDirectory(_ path: String, withAttributes: SFTPFileAttributes, context: SSHContext) async throws -> SFTPStatusCode {
        return .ok
    }
    
    func removeFile(_ path: String, context: SSHContext) async throws -> SFTPStatusCode {
        return .ok
    }
    
    func removeDirectory(_ path: String, context: SSHContext) async throws -> SFTPStatusCode {
        return .ok
    }
    
    func fileAttributes(atPath path: String, context: SSHContext) async throws -> SFTPFileAttributes {
        return .none
    }
    
    func setFileAttributes(to attributes: SFTPFileAttributes, atPath path: String, context: SSHContext) async throws -> SFTPStatusCode {
        return .ok
    }
    
    func addSymlink(linkPath: String, targetPath: String, context: SSHContext) async throws -> SFTPStatusCode {
        return .ok
    }
    
    func readSymlink(atPath path: String, context: SSHContext) async throws -> [SFTPPathComponent] {
        return []
    }
    
    func rename(oldPath: String, newPath: String, flags: UInt32, context: SSHContext) async throws -> SFTPStatusCode {
        return .ok
    }
}

struct MockDirectoryHandle: SFTPDirectoryHandle {
    let path: String
    let delegate: MockSFTPDelegate
    
    func listFiles(context: SSHContext) async throws -> [SFTPFileListing] {
        if let files = delegate.virtualFileSystem[path] {
            return [SFTPFileListing(path: files)]
        }
        return []
    }
}

