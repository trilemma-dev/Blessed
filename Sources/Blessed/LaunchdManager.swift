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
///  - install (bless) privileged executables which will run as root
///  - enable (or disable) a bundle to run as a login item
///
/// This functionality has exacting requirements in order for them to succeed; closely read each function's documentation.
///
/// ## Topics
/// ### Privileged Executables
/// - ``authorizeAndBless(message:icon:)``
/// - ``bless(executableLabel:authorization:)``
/// ### Login Items
/// - ``enableLoginItem(forBundleIdentifier:)``
/// - ``disableLoginItem(forBundleIdentifier:)``
public struct LaunchdManager {
    
    private init() { }
    
    /// Submits the executable as a launchd job.
    ///
    /// In order to use this function the following requirements must be met:
    ///  1. The calling application and target executable tool must both be signed.
    ///  2. The calling application's Info.plist must include a
    /// [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    ///  dictionary of strings. Each string is a textual representation of a code
    ///  signing requirement used to determine whether the application owns the privileged tool once installed (i.e. in order for subsequent versions to update the
    ///  installed version).
    ///
    /// Each key of `SMPrivilegedExecutables` is a reverse-DNS label for the helper tool (must be globally unique).
    /// 1. The helper tool must have an embedded Info.plist containing an
    /// [`SMAuthorizedClients`](https://developer.apple.com/documentation/bundleresources/information_property_list/smauthorizedclients)
    /// array of strings. Each string is a textual representation of a
    /// code signing requirement describing a client which is allowed to add and remove the tool.
    /// 2. The helper tool must have an embedded launchd plist. The only required key in this plist is the `Label` key. When the launchd plist is extracted and
    /// written to disk, the key for `ProgramArguments` will be set to an array of 1 element pointing to a standard location. You cannot specify your own
    /// program arguments, so do not rely on custom command line arguments being passed to your tool. Pass any parameters via IPC.
    /// 3. The helper tool must reside in the `Contents/Library/LaunchServices` directory inside the application bundle, and its name must be its
    /// launchd job label. So if your launchd job label is "com.apple.Mail.helper", this must be the name of the tool in your application bundle.
    ///
    /// - Parameters:
    ///   - executableLabel: The label of the privileged executable to install. This label must be one of the keys found in the
    ///  [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    ///    dictionary in this application's Info.plist.
    ///   - authorization: An authorization containing the  ``AuthorizationRight/blessPrivilegedHelper`` right.
    public static func bless(executableLabel: String, authorization: Authorization) throws {
        var unmanagedError: Unmanaged<CFError>?
        let result = SMJobBless(kSMDomainSystemLaunchd,
                                executableLabel as CFString,
                                authorization.authorizationRef,
                                &unmanagedError)
        if let error = unmanagedError?.takeUnretainedValue() {
            defer { unmanagedError?.release() }
            throw LaunchdError.fromError(originalError: error)
        } else if !result {
            throw LaunchdError.blessFailure
        }
    }
    
    /// Requests authorization and then submits the executable defined by this application's
    /// [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    /// as a launchd job.
    ///
    /// See ``Authorization/init(rights:environment:options:)`` and ``bless(executableLabel:authorization:)`` for details on
    /// this function's behavior as both are called internally.
    ///
    /// Tthe value for `bless`'s `executableLabel` parameter is determined as the key for the first entry in `SMPrivilegedExecutables` if this
    /// dictionary contains exactly one entry. Otherwise  ``LaunchdError/invalidExecutablesDictionary`` will be thrown.
    ///
    /// - Parameters:
    ///   - message: Optional message shown to the user as part of the macOS authentication dialog.
    ///   - icon: Optional file path to an image file loadable by `NSImage` which will be shown to the user as part of the macOS authentication dialog.
    public static func authorizeAndBless(message: String? = nil, icon: URL? = nil) throws {
        // Request authorization for blessing
        let rights: Set<AuthorizationRight> = [AuthorizationRight.blessPrivilegedHelper]
        var environment = Set<AuthorizationEnvironmentEntry>()
        if let message = message {
            environment.insert(AuthorizationEnvironmentEntry.forPrompt(message: message))
        }
        if let icon = icon {
            environment.insert(AuthorizationEnvironmentEntry.forIcon(icon))
        }
        let options: Set<AuthorizationOption> = [.interactionAllowed, .extendRights]
        let authorization = try Authorization(rights: rights, environment: environment, options: options)
        
        // Bless executable
        if let executables = Bundle.main.infoDictionary?["SMPrivilegedExecutables"] as? [String : String],
           executables.count == 1,
           let firstExecutable = executables.first?.key {
            try bless(executableLabel: firstExecutable, authorization: authorization)
        } else {
            throw LaunchdError.invalidExecutablesDictionary
        }
    }
    
    /// Enables a helper tool in the main app bundle’s Contents/Library/LoginItems directory.
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
    
    /// Disable a helper tool in the main app bundle’s Contents/Library/LoginItems directory.
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
}

// Adds static properties for the rights in the ServiceManagement framework.
public extension AuthorizationRight {
    /// Authorization right for blessing and installing a privileged helper tool.
    static let blessPrivilegedHelper = AuthorizationRight(name: kSMRightBlessPrivilegedHelper)
   
    /// Authorization right for modifying system daemons.
    static let modifySystemsDaemon = AuthorizationRight(name: kSMRightModifySystemDaemons)
}
