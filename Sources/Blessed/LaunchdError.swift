//
//  BlessError.swift
//  Blessed
//
//  Created by Josh Kaplan on 2021-10-21
//

import Foundation
import ServiceManagement

/// Errors thrown by ``LaunchdManager``.
public enum LaunchdError: Error {
    /// An internal failure has occurred.
    case internalFailure
    /// The Application's code signature does not meet the requirements to perform the operation.
    case invalidSignature
    /// The ``AuthorizationRight/blessPrivilegedHelper`` right was required, but the ``Authorization`` instance did not contain this right.
    case authorizationFailure
    /// The specified path does not exist or the tool at the specified path is not valid.
    case toolNotValid
    /// A job with the given label could not be found.
    case jobNotFound
    /// The service required to perform this operation is unavailable or is no longer accepting requests.
    case serviceUnavailable
    ///  [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    ///  entry is missing in the application's Info.plist.
    ///
    /// Officially public, but not documented.
    case jobPlistNotFound
    /// The helper tool is on the permanently disabled services list.
    ///
    /// Officially public, but not documented.
    ///
    /// This list can be queried via `launchctl print-disabled system`.  A disabled service can be reenabled via
    /// `sudo launchctl enable system/<Label>`.
    case jobMustBeEnabled
    /// The property list of this application or the helper tool was invalid.
    ///
    /// Officially public, but not documented.
    case invalidPlist
    /// Other errors returned by the Service Management framework.
    case other(CFError)
    
    
    // Errors specific to this Swift implementation wrapper
    
    /// Blessing the tool failed.
    case blessFailure
    ///  [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    /// dictionary does not contain exactly one entry.
    case invalidExecutablesDictionary
    /// Unable to enable login item.
    case loginItemNotEnabled
    /// Unable to disable login item.
    case loginItemNotDisabled
    
    private static let mapping = [
        kSMErrorInternalFailure:        internalFailure,
        kSMErrorInvalidSignature:       invalidSignature,
        kSMErrorAuthorizationFailure:   authorizationFailure,
        kSMErrorToolNotValid:           toolNotValid,
        kSMErrorJobNotFound:            jobNotFound,
        kSMErrorServiceUnavailable:     serviceUnavailable,
        kSMErrorJobPlistNotFound:       jobPlistNotFound,
        kSMErrorJobMustBeEnabled:       jobMustBeEnabled,
        kSMErrorInvalidPlist:           invalidPlist
    ]
    
    internal static func fromError(originalError: CFError) -> LaunchdError {
        let error: LaunchdError
        if let domain = CFErrorGetDomain(originalError) as String?,
           domain == "CFErrorDomainLaunchd",
           let code = CFErrorGetCode(originalError) as Int?,
           let mappedError = mapping[code] {
             error = mappedError
        } else {
            error = other(originalError)
        }
        
        return error
    }
}
