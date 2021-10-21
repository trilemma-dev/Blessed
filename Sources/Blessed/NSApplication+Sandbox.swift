//
//  NSApplication+Sandbox.swift
//  Blessed
//
//  Created by Josh Kaplan on 2021-10-21
//

import Foundation
import AppKit

extension NSApplication {
    /// Indicates whether the app is sandboxed.
    ///
    /// Authorization is not supported within an App Sandbox because it allows privilege escalation.
    ///
    /// - Throws: ``AuthorizationError`` if unable to determine whether this app is sandboxed.
    /// - Returns: If the app is sandboxed.
    public func isSandboxed() throws -> Bool {
        // Code representations of this running code
        let currentCode: SecCode = try AuthorizationError.throwIfFailure { currentCode in
            SecCodeCopySelf(SecCSFlags(), &currentCode)
        }
        
        // Static representation of this running code
        let currentStaticCode: SecStaticCode = try AuthorizationError.throwIfFailure { currentStaticCode in
            SecCodeCopyStaticCode(currentCode, SecCSFlags(), &currentStaticCode)
        }
        
        // Signing information dictionary, expected to contain entitlements dictionary
        let info: NSDictionary = try AuthorizationError.throwIfFailure { info in
            let flags = SecCSFlags(rawValue: kSecCSDynamicInformation)
            var cfInfo = info as CFDictionary?
            return SecCodeCopySigningInformation(currentStaticCode, flags, &cfInfo)
        }
        
        // Entitlements dictionary should be present
        guard let entitlements = info[kSecCodeInfoEntitlementsDict] as? NSDictionary else {
            // This isn't expected to happen, but we need to throw something if it does
            // Throwing internalError isn't perfectly correct, but it's preferable to creating an error just for this
            throw AuthorizationError.internalError
        }
        
        // Whether this app has the sandbox entitlement and what its value is
        let sandboxed: Bool
        if let sandboxEntitlement = entitlements["com.apple.security.app-sandbox"] as? Bool {
            sandboxed = sandboxEntitlement
        } else { // Lack of boolean entitlement value means the app isn't sandboxed
            sandboxed = false
        }
        
        return sandboxed
    }
}
