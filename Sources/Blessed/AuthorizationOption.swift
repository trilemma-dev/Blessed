//
//  AuthorizationOption.swift
//  Blessed
//  
//  Created by Josh Kaplan on 2021-10-21
//

import Foundation

/// Configuration options when requesting authorization.
public enum AuthorizationOption {
    /// Permits user interaction as needed.
    ///
    /// If this option is specified, the Security Server is permitted to interact with the user as needed.
    case interactionAllowed
    /// Permits the Security Server to attempt to grant the rights requested.
    ///
    /// Once the Security Server denies one right, it ignores the remaining requested rights.
    case extendRights
    /// Permits the Security Server to grant rights on an individual basis.
    ///
    /// If this and the ``extendRights`` option are specified, the Security Server grants or denies rights on an individual basis and all rights are checked.
    case partialRights
    /// Instructs the Security Server to revoke authorization.
    ///
    /// If this option is specified, the Security Server revokes authorization from the process as well as from any other process that is sharing the authorization. If
    /// not specified, the Security Server revokes authorization from the process but not from other processes that share the authorization.
    case destroyRights
    /// Instructs the Security Server to preauthorize the rights requested.
    case preAuthorize
}

internal extension Set where Element == AuthorizationOption {
    func asAuthorizationFlags() -> AuthorizationFlags {
        var flags = [AuthorizationFlags]()
        for element in self {
            switch element {
                case .interactionAllowed:
                    flags.append(AuthorizationFlags.interactionAllowed)
                case .extendRights:
                    flags.append(AuthorizationFlags.extendRights)
                case .partialRights:
                    flags.append(AuthorizationFlags.partialRights)
                case .destroyRights:
                    flags.append(AuthorizationFlags.destroyRights)
                case .preAuthorize:
                    flags.append(AuthorizationFlags.preAuthorize)
            }
        }
        
        return AuthorizationFlags(flags)
    }
}
