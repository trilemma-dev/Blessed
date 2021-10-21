//
//  AuthorizationPolicyDatabase.swift
//  Blessed
//
//  Created by Josh Kaplan on 2021-10-21
//

import Foundation

// Extension of AuthorizationRight to implement functionality from the Policy Database. This corresponds to the
// following functions:
//  - AuthorizationRightGet
//  - AuthorizationRightSet
//  - AuthorizationRightRemove
extension AuthorizationRight {
    
    /// Retrieves the definition for this right from the Policy Database.
    ///
    /// - Returns: The definition of this right or `nil` if does not exist in the Policy Database.
    public func retrieveDefinition() throws -> AuthorizationRightDefinition? {
        // From the documentation for AuthorizationRightGet:
        //  - errAuthorizationDenied -60005 No definition found.
        return try self.name.withCString { namePointer in
            let definition: AuthorizationRightDefinition?
            var entries: CFDictionary?
            let result = AuthorizationRightGet(namePointer, &entries)
            if result == errAuthorizationSuccess, let entries = entries {
                definition = AuthorizationRightDefinition(entries: entries)
            } else if result == errAuthorizationDenied {
                definition = nil
            } else {
                throw AuthorizationError.fromResult(result)
            }
            
            return definition
        }
    }
    
    /// Determines whether this right is defined in the Policy Database.
    ///
    /// - Returns: If this right is defined in the Policy Database.
    public func isDefined() throws -> Bool {
        // From the documentation for AuthorizationRightGet:
        //  - Passing in NULL will just check if there is a definition.
        //  - errAuthorizationDenied -60005 No definition found.
        return try self.name.withCString { namePointer in
            let exists: Bool
            let result = AuthorizationRightGet(namePointer, nil)
            if result == errAuthorizationSuccess {
                exists = true
            } else if result == errAuthorizationDenied {
                exists = false
            } else {
                throw AuthorizationError.fromResult(result)
            }
            
            return exists
        }
    }
    
    /// Creates or updates right in the Policy Database.
    ///
    /// The right you define must be an explicit right with no wildcards. Wildcard rights are for use by system administrators for site configuration.
    ///
    /// You can use this function to define a new right or modify an existing definition.
    ///
    /// - Parameters:
    ///   - rules: One or more instances defining the behavior of this right.
    ///   - authorization: Valid authorization used to authorize modifications. If not provided, one will be created.
    ///   - descriptionKey: Used as a key for looking up localized descriptions. If no localization is found, this is the description itself.
    ///   - bundle: A bundle to get localizations from if not the main bundle.
    ///   - localeTableName: A string representing a table name from which to get localizations. Pass `nil` if you have no localizations or you wish to use
    ///                      the localizations available in `Localizable.strings`.
    ///   - comment: Comments for the administrator; as opposed to (localized) descriptions presented to the user.
    public func createOrUpdateDefinition(rules: Set<AuthorizationRightRule>,
                                         authorization: Authorization? = nil,
                                         descriptionKey: String? = nil,
                                         bundle: Bundle? = nil,
                                         localeTableName: String? = nil,
                                         comment: String? = nil) throws {
        try self.name.withCString { namePointer in
            // Convert from Bundle to CFBundle
            var cfBundle: CFBundle?
            if let bundle = bundle {
                cfBundle = CFBundleCreate(nil, bundle.bundleURL as CFURL)
            }
            
            // Construct the right definition
            let rightDefinition = NSMutableDictionary(capacity: rules.count + (comment == nil ? 0 : 1))
            for rule in rules {
                rightDefinition[kAuthorizationRightRule] = rule.name
            }
            if let comment = comment {
                rightDefinition[kAuthorizationComment] = comment
            }
            
            // If necessary creation an Authorization instance
            let auth: Authorization
            if let authorization = authorization {
                auth = authorization
            } else {
                auth = try Authorization()
            }
            
            try AuthorizationError.throwIfFailure {
                AuthorizationRightSet(auth.authorizationRef,
                                      namePointer,
                                      rightDefinition,
                                      descriptionKey as CFString?,
                                      cfBundle,
                                      localeTableName as CFString?)
            }
        }
    }
    
    /// Requests to remove this right from the Policy Database.
    ///
    /// This right must be an explicit right with no wildcards. Wildcard rights are for use by system administrators for site configuration.
    ///
    /// - Parameters:
    ///   - authorization: Valid authorization for Policy Database modifications.
    public func removeDefinition(authorization: Authorization) throws {
        try self.name.withCString { namePointer in
            try AuthorizationError.throwIfFailure {
                AuthorizationRightRemove(authorization.authorizationRef, namePointer)
            }
        }
    }
}

/// An authorization right rule is an ``AuthorizationRight`` used to define other rights.
///
/// See ``CannedAuthorizationRightRules`` for rules which ship with macOS.
public typealias AuthorizationRightRule = AuthorizationRight

/// Canned rules that ship with macOS which can be used when creating or updating a right definition.
public struct CannedAuthorizationRightRules {
    
    private init() { }
    
    /// The user must be an administrator.
    public static let isAdmin: AuthorizationRightRule = AuthorizationRight(name: kAuthorizationRuleIsAdmin)
    /// The user must authenticate as an administrator.
    public static let authenticateAsAdmin: AuthorizationRightRule =
        AuthorizationRight(name: kAuthorizationRuleAuthenticateAsAdmin)
    /// The user must authenticate as the session owner (logged-in user).
    public static let authenticateAsSessionUser: AuthorizationRightRule =
        AuthorizationRight(name: kAuthorizationRuleAuthenticateAsSessionUser)
    /// Always allows the specified right.
    public static let classAllow: AuthorizationRightRule = AuthorizationRight(name: kAuthorizationRuleClassAllow)
    /// Always denies the specified right.
    public static let classDeny: AuthorizationRightRule = AuthorizationRight(name: kAuthorizationRuleClassDeny)
}

/// Definition of an authorization right in the Policy Database.
///
/// The vast majority of the information about a right is not publicly documented. However, most of it is privately documented in
/// [`AuthorizationTagsPriv.h`](https://opensource.apple.com/source/Security/Security-58286.41.2/OSX/libsecurity_authorization/lib/AuthorizationTagsPriv.h.auto.html) as
/// [publicly noted by Apple](https://developer.apple.com/documentation/security/authorization_plug-ins/using_authorization_plug-ins):
/// "The keys used in the dictionary entry are listed in Authorization Name Tags plus those in the file AuthorizationTagsPriv.h."
///
/// As such this header file is used as the basis for the optional properties in this struct and their documentation. Unless otherwise stated, a property of this struct
/// exists to access an undocumented definition entry.
///
/// ## Topics
/// ### All Properties
/// - ``entries``
/// ### Documented Properties
/// - ``comment``
/// - ``rule``
/// ### Undocumented Properties
/// - ``allowRoot``
/// - ``authenticateUser``
/// - ``button``
/// - ``class``
/// - ``created``
/// - ``defaultButton``
/// - ``defaultPrompt``
/// - ``description``
/// - ``entitled``
/// - ``entitledGroup``
/// - ``extractPassword``
/// - ``group``
/// - ``identifier``
/// - ``kOfN``
/// - ``mechanisms``
/// - ``modified``
/// - ``passwordOnly``
/// - ``requireAppleSigned``
/// - ``requirement``
/// - ``sessionOwner``
/// - ``shared``
/// - ``timeout``
/// - ``timeoutRight``
/// - ``tries``
/// - ``version``
/// - ``VPNEntitledGroup``
public struct AuthorizationRightDefinition {
    /// All of the entries which define this right.
    ///
    /// Convenience read-only properties exist for all known keys. Almost all of these are not publicly documented, but they are documented in
    /// [`AuthorizationTagsPriv.h`](https://opensource.apple.com/source/Security/Security-58286.41.2/OSX/libsecurity_authorization/lib/AuthorizationTagsPriv.h.auto.html).
    public let entries: [String : Any]
    
    fileprivate init(entries: CFDictionary) {
        var castEntries = [String: Any]()
        for (key, value) in entries as NSDictionary {
            if let key = key as? String {
                if let array = value as? NSArray {
                    castEntries[key] = array as [AnyObject]
                } else if let dictionary = value as? NSDictionary {
                    castEntries[key] = dictionary as? [AnyHashable: AnyObject]
                } else {
                    castEntries[key] = value
                }
            }
        }
        self.entries = castEntries
    }
    
    /// The class (in other words the "type") of right that is defined.
    public var `class`: AuthorizationRightDefinitionClass? {
        let classType: AuthorizationRightDefinitionClass?
        if let rightClass = self.entries["class"] as? String {
            switch rightClass {
                case "deny":
                    classType = .deny
                case "allow":
                    classType = .allow
                case "rule":
                    classType = .rule
                case "user":
                    classType = .user
                case "evaluate-mechanisms":
                    classType = .evaluateMechanisms
                default:
                    classType = .other(rightClass)
            }
        } else {
            classType = nil
        }
        
        return classType
    }
    
    /// Comments for the administrator on what is being customized here; as opposed to (localized) descriptions presented to the user.
    ///
    /// This entry **is** publicly documented.
    public var comment: String? {
        self.entries[kAuthorizationComment] as? String
    }
    
    /// The rules which define this right. Each rule is expected to be a right which exists in the Policy Database.
    ///
    /// This entry **is** publicly documented.
    public var rule: [AuthorizationRight]? {
        var ruleRights: [AuthorizationRight]?
        if let ruleElements = self.entries[kAuthorizationRightRule] as? [String] {
            ruleRights = [AuthorizationRight]()
            for element in ruleElements {
                ruleRights?.append(AuthorizationRight(name: element))
            }
        }
        
        return ruleRights
    }
    
    /// When the definition was initially created.
    public var created: Date? {
        var date: Date?
        if let createdInterval = self.entries["created"] as? TimeInterval {
            date = Date(timeIntervalSinceReferenceDate: createdInterval)
        }
        
        return date
    }
    
    /// When the definition was last modified.
    public var modified: Date? {
        var date: Date?
        if let createdInterval = self.entries["modified"] as? TimeInterval {
            date = Date(timeIntervalSinceReferenceDate: createdInterval)
        }
        
        return date
    }
    
    /// Undocumented.
    public var version: Int? {
        self.entries["version"] as? Int
    }
    
    /// Undocumented.
    public var identifier: String? {
        self.entries["identifier"] as? String
    }
    
    /// Undocumented, but in practice appears to be the designated requirement of the application which created the right definition.
    public var requirement: SecRequirement? {
        var requirement: SecRequirement?
        if let requirementString = self.entries["requirement"] as? String {
            SecRequirementCreateWithString(requirementString as CFString, SecCSFlags(), &requirement)
        }
        
        return requirement
    }
    
    /// Hint for internal authorization use.
    public var tries: Int? {
        return self.entries["tries"] as? Int
    }
    
    /// Group specification for user rules.
    public var group: String? {
        return self.entries["group"] as? String
    }
    
    /// K specification for k-of-n.
    public var kOfN: Int? {
        return self.entries["k-of-n"] as? Int
    }

    /// A sequence of mechanisms to be evaluated.
    public var mechanisms: [AuthorizationMechanism]? {
        var mechanisms: [AuthorizationMechanism]?
        
        if let mechanismRawValues = self.entries["mechanisms"] as? [String] {
            mechanisms = [AuthorizationMechanism]()
            for rawValue in mechanismRawValues {
                if let mechanism = AuthorizationMechanism(rawValue: rawValue) {
                    mechanisms?.append(mechanism)
                }
            }
        }
        
        return mechanisms
    }

    /// Timeout, if any, when a remembered right expires.
    ///
    /// Special values:
    ///   - Not specified retains previous behavior: most privileged, credential-based.
    ///   - Zero grants the right once (can be achieved with zero credential timeout, needed?)
    ///   - All other values are interpreted as number of seconds since granted.
    public var timeoutRight: Int? {
        return self.entries["timeout-right"] as? Int
    }
    
    /// Timeout, if any, for the use of cached credentials when authorizing rights.
    ///
    /// If not specified allows for any credentials regardless of age; rights will be remembered in authorizations, removing a credential does not stop it from
    /// granting this right, specifying a zero timeout for the right will delegate it back to requiring a credential.
    ///
    /// All other values are interpreted as number of seconds since the credential was created.
    ///
    /// Zero only allows for the use of credentials created "now" (this is deprecated).
    public var timeout: Int? {
        return self.entries["timeout"] as? Int
    }

    /// Indicates whether credentials acquired during authorization are added to the shared pool.
    public var shared: Bool? {
        return self.entries["shared"] as? Bool
    }

    /// Indicates whether to grant a right purely because the caller is root.
    public var allowRoot: Bool? {
        return self.entries["allow-root"] as? Bool
    }

    /// Indicates whether to grant a right based on a valid session-owner credential.
    public var sessionOwner: Bool? {
        return self.entries["session-owner"] as? Bool
    }

    /// Dictionary of localization-name and localized prompt pairs.
    public var defaultPrompt: [String : String]? {
        self.entries["default-prompt"] as? [String : String]
    }

    /// Dictionary of localization-name and localized button name pairs.
    public var defaultButton: [String : String]? {
        self.entries["default-button"] as? [String : String]
    }

    /// Default description of right.
    ///
    /// Usually localized versions are added using ``AuthorizationRight/createOrUpdateDefinition(rules:authorization:descriptionKey:bundle:localeTableName:comment:)``.
    public var description: String? {
        return self.entries["description"] as? String
    }

    /// Name of the default button.
    ///
    /// Usually localized versions are added using ``AuthorizationRight/createOrUpdateDefinition(rules:authorization:descriptionKey:bundle:localeTableName:comment:)``.
    public var button: String? {
        return self.entries["button"] as? String
    }

    /// Indicates whether to authenticate the user requesting authorization.
    public var authenticateUser: Bool? {
        return self.entries["authenticate-user"] as? Bool
    }

    /// Indicates that the password should be extracted to the context.
    public var extractPassword: Bool? {
         return self.entries["extract-password"] as? Bool
     }

    /// Indicates whether to grant a right based on the entitlement.
    public var entitled: Bool? {
         return self.entries["entitled"] as? Bool
     }

    /// Indicates whether to grant a right base on the entitlement and if the user is a member of ``AuthorizationRightDefinition/group``.
    public var entitledGroup: Bool? {
         return self.entries["entitled-group"] as? Bool
    }
    
    /// Indicates whether to grant a right base on the VPN entitlement  and if the user is a member of ``AuthorizationRightDefinition/group``.
    public var VPNEntitledGroup: Bool? {
         return self.entries["vpn-entitled-group"] as? Bool
     }

    /// Require the caller to be signed by Apple.
    public var requireAppleSigned: Bool? {
         return self.entries["require-apple-signed"] as? Bool
     }

    /// Default `false` - if `true`, all alternative authentication methods like smart cards are disabled for this rule, only password is allowed.
    public var passwordOnly: Bool? {
         return self.entries["password-only"] as? Bool
     }
}

/// The type of authorization right being defined.
///
/// These cases are not publicly documented and so ``other(_:)`` exists to handle any unanticipated values.
public enum AuthorizationRightDefinitionClass {
    /// Denies anything.
    case deny
    /// Allows anything.
    case allow
    /// Undocumented.
    case rule
    /// Undocumented.
    case user
    /// Implementation of policies that are not included in the standard authorization configuration.
    case evaluateMechanisms
    /// Unanticipated class value. The associated value is its raw string representation.
    case other(String)
}

/// A code module that performs one step in the authorization process.
///
/// You cannot create this struct; it is returned from ``AuthorizationRightDefinition/mechanisms``.
///
/// See [Using Authorization Plug-ins](https://developer.apple.com/documentation/security/authorization_plug-ins/using_authorization_plug-ins)
/// for more information about mechanisms.
public struct AuthorizationMechanism {
    // From https://developer.apple.com/documentation/security/authorization_plug-ins/using_authorization_plug-ins:
    // Notice that each plug-in is identified by the name of the plug-in, a colon, and the name of the mechanism;
    // for example SendFaxPlugin:SelectFaxMachine where SelectFaxMachine is a mechanism in the plug-in
    // SendFaxPlugin.
    
    // To have a specific mechanism run with root privileges, add a comma and the word privileged to the mechanism
    // name; for example:
    // SendFaxPlugin:ChangeUserPIN,privileged
    
    /// The name of the plugin containing the mechanism's code.
    public let plugin: String
    /// The name of the mechanism.
    public let mechanism: String
    /// Whether the mechanism is privileged and is therefore run with root privileges.
    public let isPrivileged: Bool
    
    /// The on disk location of the plugin bundle containing the mechanism's code.
    ///
    /// The bundle may not exist, but if it does exist this is where it must be located to be invoked.
    public var pluginLocation: URL {
        // Based on:
        // To implement the policy, you could write a plug-in called SendFaxPlugin that contains two mechanisms:
        // SelectFaxMachine and GetUserPIN. You would add your plug-in code to the folder
        // /Library/Security/SecurityAgentPlugins as a bundle called SendFaxPlugin.bundle
        return URL(fileURLWithPath: "/Library/Security/SecurityAgentPlugins/\(self.plugin).bundle")
    }
    
    fileprivate init?(rawValue: String) {
        let parts = rawValue.split(separator: ":")
        
        // plugin
        if parts.count == 2,
           let firstPartSubstring = parts.first {
            self.plugin = String(firstPartSubstring)
        } else {
            return nil
        }
        
        // mechanism & privileged
        if parts.count == 2,
           let secondPartSubstring = parts.last {
            let secondPart = String(secondPartSubstring)
            if secondPart.hasSuffix(",privileged"),
               let mechanismPartSubstring = secondPart.split(separator: ",").first {
                self.isPrivileged = true
                self.mechanism = String(mechanismPartSubstring)
            } else {
                self.isPrivileged = false
                self.mechanism = secondPart
            }
        } else {
            return nil
        }
    }
}
