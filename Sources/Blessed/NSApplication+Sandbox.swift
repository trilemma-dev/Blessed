//
//  NSApplication+Sandbox.swift
//  Blessed
//
//  Created by Josh Kaplan on 2021-10-21
//

import Foundation
import AppKit

extension NSApplication {
    /// A Boolean value indicating whether this app is sandboxed.
    ///
    /// The value of this property is `true` if the
    /// [App Sandbox Entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_app-sandbox)
    /// is present and has a value of `true`, otherwise it is `false`.
    ///
    /// >Important: Authorization is not supported within an App Sandbox because it allows privilege escalation.
    public var isSandboxed: Bool {
        guard let task = SecTaskCreateFromSelf(nil) else {
            // The documentation for SecTaskCreateFromSelf mention an error can occur resulting in a nil return, but
            // lacks any information under what conditions that can occur. In practice, none have been observed.
            fatalError("SecTaskCreateFromSelf returned nil")
        }
        
        let entitlementName = "com.apple.security.app-sandbox" as CFString
        guard let entitlement = SecTaskCopyValueForEntitlement(task, entitlementName, nil) else {
            // Lack of entitlement value means the app isn't sandboxed.
            return false
        }
        
        guard CFGetTypeID(entitlement) == CFBooleanGetTypeID(), let boolValue = (entitlement as? Bool) else {
            // The entitlement value must be a boolean value. If it's not, then it's presumbly not sandboxed.
            return false
        }
        
        return boolValue
    }
}
