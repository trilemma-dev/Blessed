//
//  PrivilegedHelperManager.swift
//  Blessed
//
//  Created by Josh Kaplan on 2021-10-21
//

import Authorized
import Foundation
import ServiceManagement

/// Functions for blessing priviliged helper tools.
///
/// This functionality has exacting requirements in order for them to succeed; closely read each function's documentation.
///
/// ## Topics
/// ### Authorize & Bless
/// - ``authorizeAndBless(message:icon:)-1ztfe``
/// - ``authorizeAndBless(message:icon:)-7bz4p``
/// ### Bless
///  - ``bless(label:authorization:)``
public class PrivilegedHelperManager {
    
    private init() { }
    
    /// The shared privileged helper manager for the process.
    public static var shared = PrivilegedHelperManager()
    
    /// Submits a privileged helper tool as a launchd job.
    ///
    /// In order to successfully use this function the following requirements must be met:
    /// 1. The app calling this function **must** be signed.
    /// 2. The helper tool **must** be located in the `Contents/Library/LaunchServices` directory inside the app's bundle.
    /// 3. The helper tool **must** be an executable, not an app bundle.
    /// 4. The helper tool **must** be signed.
    /// 5. The helper tool **must** have an embedded launchd property list.
    /// 6. The helper tool's embedded launchd property list **must** have an entry with `Label` as the key and the value **must** be the filename of the
    ///   helper tool.
    /// 7. The helper tool **must** have an embedded info property list.
    /// 8. The helper tool's embedded info property list **must** have an entry with
    ///   [`SMAuthorizedClients`](https://developer.apple.com/documentation/bundleresources/information_property_list/smauthorizedclients)
    ///   as its key and its value **must** be an array of strings. Each string **must** be a
    ///   [code signing requirement](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html).
    ///   The app **must** satisify at least one of these requirements.
    ///    - The app must satisify one or more of these requirements to install or update the helper tool.
    ///        - To update the helper tool, the app must satisfy one or more requirements of both the installed helper tool and the bundled helper tool.
    ///    - These requirements are *only* about whether an app can install or update the helper tool. They impose no restrictions on communication with the
    ///      helper tool.
    /// 9. The helper tool's embedded info property list **must** have an entry with
    ///    [`CFBundleVersion`](https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundleversion)
    ///    as its key and its value **must** be a string matching the format described in `CFBundleVersion`'s documentation.
    ///     - This requirement is *not* documented by Apple, but is enforced.
    ///     - While not documented by Apple, calling this function will not overwrite an existing installation of a helper tool with one that has an equal or lower
    ///       value for its `CFBundleVersion` entry.
    ///     - Despite Apple requiring the info property list contain a key named `CFBundleVersion`, the helper tool **must** be a Command Line Tool and
    ///       **must not** be a bundle.
    /// 10. The app's Info.plist **must** have an entry with
    ///    [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    ///    as its key and its value must be a dictionary. Each dictionary key **must** be a helper tool's filename; for example
    ///    "com.example.SwiftAuthorizationApp.helper". Each dictionary value **must** be a string representation of a code signing requirement that the helper
    ///    tool satisfies.
    ///
    /// In addition to the above requirements, the filename of the helper tool **should** be reverse-DNS format. For example, if the app has the bundle identifier
    /// "com.example.SwiftAuthorizationApp" then the helper tool **may** have a filename of "com.example.SwiftAuthorizationApp.helper".
    ///
    /// - Parameters:
    ///   - label: The label of the helper tool executable to install. This label must be one of the keys found in the
    ///  [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    ///    dictionary in this app's Info.plist.
    ///   - authorization: An authorization containing the  `AuthorizationRight.blessPrivilegedHelper` right.
    /// - Throws: ``BlessError`` if unable to bless.
    public func bless(label: String, authorization: Authorization) throws {
        var unmanagedError: Unmanaged<CFError>?
        let result = SMJobBless(kSMDomainSystemLaunchd,
                                label as CFString,
                                authorization.authorizationRef,
                                &unmanagedError)
        
        if let error = unmanagedError?.takeRetainedValue() {
            throw BlessError(underlyingError: error, label: label, authorization: authorization)
        }
        
        guard result else {
            throw BlessError(underlyingError: nil, label: label, authorization: authorization)
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
            guard let executables = Bundle.main.infoDictionary?["SMPrivilegedExecutables"] as? [String : String],
                  executables.count == 1,
                  let firstExecutable = executables.first?.key else {
               fatalError("SMPrivilegedExecutables must have exactly one entry")
            }
            
            try PrivilegedHelperManager.shared.bless(label: firstExecutable, authorization: self.authorization)
        }
    }
    
    /// Synchronously requests authorization and then submits the privileged helper tool defined by this app's
    /// [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    /// as a launchd job.
    ///
    /// See `Authorization.requestRights(_:environment:options:)` and ``bless(label:authorization:)`` for details on this function's
    /// behavior as both are called internally.
    ///
    /// The value for `bless`'s `label` parameter is determined as the key for the first entry in `SMPrivilegedExecutables` if this dictionary contains
    /// exactly one entry, otherwise it is a programming error to call this function.
    ///
    /// - Parameters:
    ///   - message: Optional message shown to the user as part of the macOS authentication dialog.
    ///   - icon: Optional file path to an image file loadable by `NSImage` which will be shown to the user as part of the macOS authentication dialog.
    public func authorizeAndBless(message: String? = nil, icon: URL? = nil) throws {
        let config = try AuthorizeAndBless(message: message, icon: icon)
        try config.requestRights()
        try config.bless()
    }
    
    /// Asynchronously requests authorization and then submits the privileged helper tool defined by this app's
    /// [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    /// as a launchd job.
    ///
    /// See `Authorization.requestRights(_:environment:options:callback:)` and ``bless(label:authorization:)`` for details on
    /// this function's behavior as both are called internally.
    ///
    /// The value for `bless`'s `label` parameter is determined as the key for the first entry in `SMPrivilegedExecutables` if this dictionary contains
    /// exactly one entry, otherwise it is a programming error to call this function.
    ///
    /// - Parameters:
    ///   - message: Optional message shown to the user as part of the macOS authentication dialog.
    ///   - icon: Optional file path to an image file loadable by `NSImage` which will be shown to the user as part of the macOS authentication dialog.
    @available(macOS 10.15.0, *)
    public func authorizeAndBless(message: String? = nil, icon: URL? = nil) async throws {
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
