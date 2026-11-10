import Darwin
import Foundation
import Security

enum SecureRuntime {
    static var app: URL { HelperConstants.installedApp }
    static var protectedRoot: URL {
        URL(fileURLWithPath: "/Library/Application Support/OpenConnectGUI", isDirectory: true)
    }
    static var protectedRuntime: URL {
        protectedRoot.appendingPathComponent("runtime", isDirectory: true)
    }
    static var runtime: URL {
        protectedRuntime.appendingPathComponent("OpenConnect", isDirectory: true)
    }
    static var executable: URL { runtime.appendingPathComponent("bin/openconnect") }
    static var script: URL { runtime.appendingPathComponent("vpnc-script") }
    static var caBundle: URL { runtime.appendingPathComponent("ca-bundle.pem") }
    static var buildManifest: URL { runtime.appendingPathComponent("build-manifest.json") }
    static var libDirectory: URL { runtime.appendingPathComponent("lib", isDirectory: true) }
    static var helper: URL { protectedRuntime.appendingPathComponent("OpenConnectHelper") }
    static var authorizedUIDFile: URL { protectedRuntime.appendingPathComponent("authorized-uid") }
    static var sessionRunDir: URL {
        URL(fileURLWithPath: "/private/var/run/OpenConnectGUI", isDirectory: true)
    }

    static var bundledRuntime: URL {
        Bundle.main.bundleURL.appendingPathComponent(HelperConstants.runtimeRelativePath, isDirectory: true)
    }
    static var bundledHelper: URL {
        Bundle.main.bundleURL.appendingPathComponent(HelperConstants.helperRelativePath)
    }

    static var isSetuidHelperInstalled: Bool {
        var info = stat()
        guard lstat(helper.path, &info) == 0 else { return false }
        return info.st_uid == 0 &&
            (info.st_mode & mode_t(0o022) == 0) &&
            (info.st_mode & mode_t(S_ISUID) != 0)
    }

    static func isCallerAuthorized(uid: uid_t = getuid()) -> Bool {
        if uid == 0 {
            return true
        }
        guard (try? validateProtectedPath(authorizedUIDFile)) != nil,
              let raw = try? String(contentsOf: authorizedUIDFile, encoding: .utf8)
                .trimmingCharacters(in: .whitespacesAndNewlines),
              let allowedUID = UInt32(raw),
              allowedUID > 0 else {
            return false
        }
        return uid == uid_t(allowedUID)
    }

    static let environment = [
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": "/var/empty",
        "LANG": "en_US.UTF-8",
        "LC_ALL": "en_US.UTF-8",
        "P11_KIT_NO_USER_CONFIG": "1",
        "GNUTLS_SYSTEM_PRIORITY_FILE": "/dev/null",
        "LLVM_PROFILE_FILE": "/dev/null",
    ]

    /// Every ancestor and resource in the privileged runtime directory must be root-owned,
    /// non-writable by group/others, and free of ACL grants or symlinks.
    static func validateInstallation() throws {
        var ancestor = protectedRuntime
        while ancestor.path != "/" {
            try validateProtectedPath(ancestor)
            ancestor.deleteLastPathComponent()
        }
        guard let files = FileManager.default.enumerator(at: protectedRuntime, includingPropertiesForKeys: nil) else {
            throw VPNServiceError.message("The privileged VPN runtime is not installed yet.")
        }
        for case let file as URL in files {
            try validateProtectedPath(file)
        }
        guard FileManager.default.fileExists(atPath: caBundle.path) else {
            throw VPNServiceError.message("The packaged CA bundle is missing.")
        }
        for file in [executable, script, helper] {
            guard FileManager.default.isExecutableFile(atPath: file.path) else {
                throw VPNServiceError.message("The protected VPN runtime is incomplete.")
            }
        }
        if let libEntries = try? FileManager.default.contentsOfDirectory(atPath: libDirectory.path) {
            guard libEntries.contains(where: { $0.hasSuffix(".dylib") }) else {
                throw VPNServiceError.message("The protected VPN runtime libraries are incomplete.")
            }
        }
    }

    static func validateProtectedPath(_ url: URL) throws {
        var info = stat()
        guard lstat(url.path, &info) == 0,
              info.st_uid == 0,
              info.st_mode & mode_t(0o022) == 0,
              info.st_mode & mode_t(S_IFMT) != mode_t(S_IFLNK)
        else {
            throw VPNServiceError.message(
                "VPN runtime files must be root-owned and protected in /Library/Application Support/OpenConnectGUI."
            )
        }
        errno = 0
        if let acl = acl_get_file(url.path, ACL_TYPE_EXTENDED) {
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            var entry: acl_entry_t?
            guard acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry) != 0 else {
                throw VPNServiceError.message(
                    "The installed VPN runtime has unexpected access control permissions."
                )
            }
        } else if errno != ENOENT && errno != ENOTSUP && errno != EOPNOTSUPP {
            throw VPNServiceError.message("Cannot verify permissions of the installed VPN runtime.")
        }
    }

    static func signingRequirement(for url: URL) throws -> String {
        var code: SecStaticCode?
        var requirement: SecRequirement?
        var text: CFString?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
              SecCodeCopyDesignatedRequirement(code, [], &requirement) == errSecSuccess, let requirement,
              SecRequirementCopyString(requirement, [], &text) == errSecSuccess, let text
        else {
            throw VPNServiceError.message("The installed application and helper must be code signed.")
        }
        return text as String
    }
}
