//
//  LaunchdManager.swift
//  Blessed
//
//  Created by Josh Kaplan on 2021-10-21
//

import Foundation
import ServiceManagement

/// Register launchd services.
///
/// Functionality is provided to:
///  - install (bless) privileged helper tools which will run as root
///  - enable or disable bundles to run as login items
///
/// This functionality has exacting requirements in order for them to succeed; closely read each function's documentation.
///
/// ## Topics
/// ### Privileged Helper Tools
/// - ``authorizeAndBless(message:icon:)-9guaa``
/// - ``authorizeAndBless(message:icon:)-4qvn1``
/// - ``bless(label:authorization:)``
/// ### Login Items
/// - ``enableLoginItem(forBundleIdentifier:)``
/// - ``disableLoginItem(forBundleIdentifier:)``
public struct LaunchdManager {
    
    private init() { }
    
    /// Submits a privileged helper tool as a launchd job.
    ///
    /// In order to successfully use this function the following requirements must be met:
    /// 1. The app calling this function **must** be signed.
    /// 2. The helper tool **must** be an executable, not an app bundle.
    /// 3. The helper tool **must** be signed.
    /// 4. The helper tool **must** be located in the `Contents/Library/LaunchServices` directory inside the app's bundle.
    /// 5. The filename of the helper tool **should** be reverse-DNS format.
    ///    - If the app has the bundle identifier "com.example.SwiftAuthorizationApp" then the helper tool **may** have a filename of
    ///      "com.example.SwiftAuthorizationApp.helper".
    /// 6. The helper tool **must** have an embedded launchd property list.
    /// 7. The helper tool's embedded launchd property list **must** have an entry with `Label` as the key and the value **must** be the filename of the
    ///   helper tool.
    /// 8. The helper tool **must** have an embedded info property list.
    /// 9. The helper tool's embedded info property list **must** have an entry with
    ///   [`SMAuthorizedClients`](https://developer.apple.com/documentation/bundleresources/information_property_list/smauthorizedclients)
    ///   as its key and its value **must** be an array of strings. Each string **must** be a
    ///   [code signing requirement](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html).
    ///   The app **must** satisify at least one of these requirements.
    ///    - Only processes which meet one or more of these requirements may install or update the helper tool.
    ///    - These requirements are *only* about which processes may install or update the helper tool. They impose no restrictions on which processes can
    ///      communicate with the helper tool.
    /// 10. The helper tool's embedded info property list **must** have an entry with
    ///    [`CFBundleVersion`](https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundleversion)
    ///    as its key and its value **must** be a string matching the format described in `CFBundleVersion`'s documentation.
    ///     - This requirement is *not* documented by Apple, but is enforced.
    ///     - While not documented by Apple, calling this function will not overwrite an existing installation of a helper tool with one that has an equal or lower
    ///       value for its `CFBundleVersion` entry.
    ///     - Despite Apple requiring the info property list contain a key named `CFBundleVersion`, the helper tool **must** be a Command Line Tool and
    ///       **must not** be a bundle.
    /// 11. The app's Info.plist **must** have an entry with
    ///    [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    ///    as its key and its value must be a dictionary. Each dictionary key **must** be a helper tool's filename; for example
    ///    "com.example.SwiftAuthorizationApp.helper". Each dictionary value **must** be a string representation of a code signing requirement that the helper
    ///    tool satisfies.
    ///
    /// - Parameters:
    ///   - label: The label of the helper tool executable to install. This label must be one of the keys found in the
    ///  [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    ///    dictionary in this app's Info.plist.
    ///   - authorization: An authorization containing the  ``AuthorizationRight/blessPrivilegedHelper`` right.
    /// - Throws: ``LaunchdError`` if unable to bless.
    public static func bless(label: String, authorization: Authorization) throws {
        var unmanagedError: Unmanaged<CFError>?
        let result = SMJobBless(kSMDomainSystemLaunchd,
                                label as CFString,
                                authorization.authorizationRef,
                                &unmanagedError)
        if let error = unmanagedError?.takeUnretainedValue() {
            defer { unmanagedError?.release() }
            throw LaunchdError.fromError(originalError: error)
        } else if !result {
            throw LaunchdError.blessFailure
        }
    }
    
    /// Enables a helper tool in the main app bundle’s `Contents/Library/LoginItems` directory.
    ///
    /// This is effective only for the currently logged-in user. If this function returns successfully, the helper tool starts immediately (and upon subsequent logins)
    /// and keeps running.
    ///
    /// - Parameter forBundleIdentifier: Bundle identifier for the helper tool.
    /// - Throws: If unable to successfully enable the login item.
    public static func enableLoginItem(forBundleIdentifier identifier: String) throws {
        if !SMLoginItemSetEnabled(identifier as CFString, true) {
            throw LaunchdError.loginItemNotEnabled
        }
    }
    
    /// Disables a helper tool in the main app bundle’s `Contents/Library/LoginItems` directory.
    ///
    /// This is effective only for the currently logged-in user. If this function returns successfully, the helper tool stop immediately.
    ///
    /// - Parameter forBundleIdentifier: Bundle identifier for the helper tool.
    /// - Throws: If unable to successfully disable the login item.
    public static func disableLoginItem(forBundleIdentifier identifier: String) throws {
        if !SMLoginItemSetEnabled(identifier as CFString, false) {
            throw LaunchdError.loginItemNotDisabled
        }
    }
    
    // MARK: authorize & bless
    
    /// This private struct encapsulates the data and functions needed to perform back-to-back requests for the authorization needed to bless an executable and
    /// then to actually perform the blessing.
    ///
    /// This is factored out into its own struct so that it be used either to request authorization synchronously or asynchronously while minimizing duplication.
    private struct AuthorizeAndBless {
        let rights: Set<AuthorizationRight>
        let environment: Set<AuthorizationEnvironmentEntry>
        let options: Set<AuthorizationOption>
        let authorization: Authorization
        
        init(message: String? = nil, icon: URL? = nil) throws {
            self.rights = [.blessPrivilegedHelper]
            
            var environment = Set<AuthorizationEnvironmentEntry>()
            if let message = message {
                environment.insert(.forPrompt(message: message))
            }
            if let icon = icon {
                environment.insert(.forIcon(icon))
            }
            self.environment = environment
            
            self.options = [.interactionAllowed, .extendRights]
            self.authorization = try Authorization()
        }
        
        func requestRights() throws {
            _ = try authorization.requestRights(rights, environment: environment, options: options)
        }
        
        @available(macOS 10.15.0, *)
        func requestRights() async throws {
            _ = try await authorization.requestRights(rights, environment: environment, options: options)
        }
        
        func bless() throws {
            if let executables = Bundle.main.infoDictionary?["SMPrivilegedExecutables"] as? [String : String],
               executables.count == 1,
               let firstExecutable = executables.first?.key {
                try LaunchdManager.bless(label: firstExecutable, authorization: self.authorization)
            } else {
                throw LaunchdError.invalidExecutablesDictionary
            }
        }
    }
    
    /// Synchronously requests authorization and then submits the privileged helper tool defined by this app's
    /// [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    /// as a launchd job.
    ///
    /// See ``Authorization/requestRights(_:environment:options:)-5wtuy`` and ``bless(label:authorization:)`` for details
    /// on this function's behavior as both are called internally.
    ///
    /// Tthe value for `bless`'s `label` parameter is determined as the key for the first entry in `SMPrivilegedExecutables` if this dictionary contains
    /// exactly one entry. Otherwise  ``LaunchdError/invalidExecutablesDictionary`` will be thrown.
    ///
    /// - Parameters:
    ///   - message: Optional message shown to the user as part of the macOS authentication dialog.
    ///   - icon: Optional file path to an image file loadable by `NSImage` which will be shown to the user as part of the macOS authentication dialog.
    public static func authorizeAndBless(message: String? = nil, icon: URL? = nil) throws {
        let config = try AuthorizeAndBless(message: message, icon: icon)
        try config.requestRights()
        try config.bless()
    }
    
    /// Asynchronously requests authorization and then submits the privileged helper tool defined by this app's
    /// [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    /// as a launchd job.
    ///
    /// See ``Authorization/requestRights(_:environment:options:callback:)`` and ``bless(label:authorization:)`` for
    /// details on this function's behavior as both are called internally.
    ///
    /// Tthe value for `bless`'s `label` parameter is determined as the key for the first entry in `SMPrivilegedExecutables` if this dictionary contains
    /// exactly one entry. Otherwise  ``LaunchdError/invalidExecutablesDictionary`` will be thrown.
    ///
    /// - Parameters:
    ///   - message: Optional message shown to the user as part of the macOS authentication dialog.
    ///   - icon: Optional file path to an image file loadable by `NSImage` which will be shown to the user as part of the macOS authentication dialog.
    @available(macOS 10.15.0, *)
    public static func authorizeAndBless(message: String? = nil, icon: URL? = nil) async throws {
        let config = try AuthorizeAndBless(message: message, icon: icon)
        try await config.requestRights()
        try config.bless()
    }
}

// Adds static properties for the rights in the ServiceManagement framework.
public extension AuthorizationRight {
    /// Authorization right for blessing and installing a privileged helper tool.
    ///
    /// When using this to check or request rights, ``AuthorizationEnvironmentEntry/forPrompt(message:)`` and
    /// ``AuthorizationEnvironmentEntry/forIcon(_:)`` can be specified as environment entries.
    static let blessPrivilegedHelper = AuthorizationRight(name: kSMRightBlessPrivilegedHelper)
   
    /// Authorization right for modifying system daemons.
    static let modifySystemsDaemon = AuthorizationRight(name: kSMRightModifySystemDaemons)
}
