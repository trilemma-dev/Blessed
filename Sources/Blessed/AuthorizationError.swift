//
//  AuthorizationError.swift
//  Blessed
//
//  Created by Josh Kaplan on 2021-10-21
//

import Foundation

/// Errors thrown by the authorization functions.
public enum AuthorizationError: Error {
    /// The authorization rights are invalid.
    case invalidSet
    /// The authorization reference is invalid.
    case invalidRef
    /// The authorization tag is invalid.
    case invalidTag
    /// The returned authorization is invalid.
    case invalidPointer
    /// The authorization was denied.
    case denied
    /// The authorization was canceled by the user.
    case canceled
    /// The authorization was denied since no user interaction was possible.
    case interactionNotAllowed
    /// Unable to obtain authorization for this operation.
    case internalError
    /// The authorization is not allowed to be converted to an external format.
    case externalizeNotAllowed
    /// The authorization is not allowed to be created from an external format.
    case internalizeNotAllowed
    /// The provided option flag(s) are invalid for this authorization operation.
    case invalidFlags
    /// The specified program could not be executed.
    case toolExecuteFailure
    /// An invalid status was returned during execution of a privileged tool.
    case toolEnvironmentError
    /// The requested socket address is invalid (must be 0-1023 inclusive).
    case badAddress
    /// Represents other errors.
    case other(OSStatus)
    
    private static let mapping = [
        errAuthorizationInvalidSet:             invalidSet,
        errAuthorizationInvalidRef:             invalidRef,
        errAuthorizationInvalidTag:             invalidTag,
        errAuthorizationInvalidPointer:         invalidPointer,
        errAuthorizationDenied:                 denied,
        errAuthorizationCanceled:               canceled,
        errAuthorizationInteractionNotAllowed:  interactionNotAllowed,
        errAuthorizationInternal:               internalError,
        errAuthorizationExternalizeNotAllowed:  externalizeNotAllowed,
        errAuthorizationInternalizeNotAllowed:  internalizeNotAllowed,
        errAuthorizationInvalidFlags:           invalidFlags,
        errAuthorizationToolExecuteFailure:     toolExecuteFailure,
        errAuthorizationToolEnvironmentError:   toolEnvironmentError,
        errAuthorizationBadAddress:             badAddress
    ]
    
    /// Wrap an authorization function in this call and it will throw an ``AuthorizationError`` if the result code is anything besides `errSecSuccess`.
    internal static func throwIfFailure(_ authorizationFunction: () -> (OSStatus)) throws {
        let result = authorizationFunction()
        if result != errSecSuccess {
            throw fromResult(result)
        }
    }
    
    /// Wrap an authorization function which requires a parameter to be populated.  An ``AuthorizationError`` will be thrown unless the result
    /// code was `errSecSuccess` and the value wasn't `nil`. If no error was thrown, the value is returned unwrapped.
    internal static func throwIfFailure<T>(_ authorizationFunction: (inout T?) -> (OSStatus)) throws -> T {
        var value: T?
        let result = authorizationFunction(&value)
        if result == errSecSuccess, let value = value {
            return value
        } else {
            throw fromResult(result)
        }
    }
    
    /// Returns the corresponding ``AuthorizationError`` case for `result` or ``AuthorizationError/other(_:)`` if the value has no
    /// corresponding case.
    internal static func fromResult(_ result: OSStatus) -> AuthorizationError {
        let error: AuthorizationError
        if let mappedError = mapping[result] {
            error = mappedError
        } else {
            error = other(result)
        }
        
        return error
    }
}
