//
//  Authorization.swift
//  Blessed
//
//  Created by Josh Kaplan on 2021-10-21
//

import Foundation

/// A representation of macOS's Security Server authorization.
///
/// > Tip: This class conforms to [`Codable`](https://developer.apple.com/documentation/swift/codable) and so can be serialized and
/// deserialized for convenient transference between processes.
///
/// ## Topics
/// ### Initializers
/// - ``init()``
/// - ``init(rights:environment:options:)``
///
/// ### Rights
/// - ``requestRights(_:environment:options:)``
/// - ``requestRightsAsync(_:environment:options:callback:)``
/// - ``checkRights(_:environment:options:)``
/// - ``destroyRights()``
///
/// ### Info
/// - ``retrieveInfo(tag:)``
///
/// ### Compatibility
/// - ``authorizationRef``
///
/// ### Codable
/// - ``init(from:)``
/// - ``encode(to:)``
public class Authorization: Codable {
    
    /// Returns the underlying [`AuthorizationRef`](https://developer.apple.com/documentation/security/authorizationref).
    ///
    /// This reference is only valid during the lifetime of its enclosing ``Authorization`` instance's lifetime.
    public let authorizationRef: AuthorizationRef
    
    /// Creates a new default instance.
    ///
    /// For applications that require a one-time authorization, see ``init(rights:environment:options:)``.
    public convenience init() throws {
        try self.init(rights: [], environment: [], options: [])
    }
    
    /// Creates a new customized instance.
    ///
    /// Authorizing rights with this initializer is most useful for applications that require a one-time authorization. Otherwise use ``init()`` and make subsequent
    /// calls to ``requestRights(_:environment:options:)`` or
    /// ``requestRightsAsync(_:environment:options:callback:)``.
    ///
    /// When ``AuthorizationOption/interactionAllowed`` is provided, user interaction will happen when required. Failing to provide this option will
    /// result in this initializer throwing ``AuthorizationError/interactionNotAllowed`` when interaction is required.
    ///
    /// Providing ``AuthorizationOption/extendRights`` will extend the currently available rights. If this option is provided and initialization
    /// succeeds then all the rights requested were granted. If this option is not provided the operation will almost certainly succeed, but no attempt will be made to
    /// make the requested rights available. Call ``Authorization/requestRights(_:environment:options:)`` or
    /// ``Authorization/requestRightsAsync(_:environment:options:callback:)`` to figure out which of the requested rights were
    /// granted.
    ///
    /// Providing ``AuthorizationOption/partialRights`` will cause this initializer to succeed if only some of the requested rights were granted. Unless
    /// this option is provided this initializer will throw an error if not all the requested rights could be obtained.
    ///
    /// Providing ``AuthorizationOption/preAuthorize`` will preauthorize the requested rights so that at a later time the obtained rights can be used in a
    /// different process. Rights which can't be preauthorized will be treated as if they were authorized for the sake of throwing an error (in other words if all rights
    /// are either authorized or could not be preauthorized this initializer will still succeed).
    ///
    /// The rights which could not be preauthorized are not currently authorized and may fail to authorize when a later call to
    /// ``requestRights(_:environment:options:)`` or ``requestRightsAsync(_:environment:options:callback:)`` is
    /// made, unless the ``AuthorizationOption/extendRights`` and ``AuthorizationOption/interactionAllowed`` options are provided.
    /// Even then they might still fail if the user does not supply the correct credentials.
    ///
    /// - Parameters:
    ///   - rights: A set of ``AuthorizationRight`` instances containing rights for which authorization is being requested.  If the set is empty, this
    ///             instance can be valid, but will be authorized for nothing.
    ///   - environment: A set of ``AuthorizationEnvironmentEntry`` instances containing environment state used when making the authorization
    ///                  decision. Can be an empty set if no environment state needs to be provided.
    ///   - options: A set of ``AuthorizationOption`` instances to configure this authorization. Can be an empty set if no options are needed.
    public init(rights: Set<AuthorizationRight>,
                environment: Set<AuthorizationEnvironmentEntry>,
                options: Set<AuthorizationOption>) throws {
        // This double-level nesting is necessary because the sets passed to the closures rely internally on the
        // withUnsafeMutableBufferPointer() function which has a pointer only valid within the scope of the closure.
        // All of the pointers need to be in scope when the AuthorizationCreate() call is made.
        self.authorizationRef = try rights.withUnsafePointer { rightsPointer in
            return try environment.withUnsafePointer { environmentPointer in
                return try AuthorizationError.throwIfFailure { authorization in
                    AuthorizationCreate(rightsPointer, environmentPointer, options.asAuthorizationFlags(), &authorization)
                }
            }
        }
    }
    
    /// Checks if a user has authorization for a set of rights without granting any of them.
    ///
    /// The Security Server will attempt to authorize the requested rights without actually granting the rights. If you are not going to create an
    /// ``Authorization`` instance, then use this function to determine if a user has authorization without granting any rights.
    ///
    /// - Parameters:
    ///   - rights: A set of ``AuthorizationRight`` instances containing rights for which authorization is being determined.  If the set is empty, this
    ///             function will only throw an error if there are configuration issues due to the values passed to the other parameters.
    ///   - environment: A set of ``AuthorizationEnvironmentEntry`` instances containing environment state used when making the authorization
    ///                  decision. Can be an empty set if no environment state needs to be provided.
    ///   - options: A set of ``AuthorizationOption`` instances to configure this call. Can be an empty set if no options are needed.
    ///              ``AuthorizationOption/destroyRights`` will always be implicitly included regardless of whether it is provided.
    /// - Throws: If the user could not or did not grant authorization for the provided rights.
    public static func checkRights(_ rights: Set<AuthorizationRight>,
                                   environment: Set<AuthorizationEnvironmentEntry>,
                                   options: Set<AuthorizationOption>) throws {
        // This double-level nesting is necessary because the sets passed to the closures rely internally on the
        // withUnsafeMutableBufferPointer() function which has a pointer only valid within the scope of the closure.
        // All of the pointers need to be in scope when the AuthorizationCreate() call is made.
        try rights.withUnsafePointer { rightsPointer in
            try environment.withUnsafePointer { environmentPointer in
                var options = options
                options.insert(.destroyRights)
                try AuthorizationError.throwIfFailure {
                    AuthorizationCreate(rightsPointer, environmentPointer, options.asAuthorizationFlags(), nil)
                }
            }
        }
    }
    
    /// Creates a new instance from a serialized form.
    ///
    /// - Parameter decoder: Decoder which should contain a serialization of ``Authorization``.
    required public init(from decoder: Decoder) throws {
        let serialization = try decoder.singleValueContainer().decode(Data.self)
        self.authorizationRef = try Authorization.deserialize(from: serialization)
    }
    
    /// Deserializes a `Data` instance into an `AuthorizationRef`.
    private static func deserialize(from serialization: Data) throws -> AuthorizationRef {
        // Convert data into authorization external form
        var int8Array = [CChar](repeating: 0, count: kAuthorizationExternalFormLength)
        for index in 0...kAuthorizationExternalFormLength - 1 {
            int8Array[index] = CChar(bitPattern: serialization[index])
        }
        let bytes = (int8Array[0],  int8Array[1],  int8Array[2],  int8Array[3],
                     int8Array[4],  int8Array[5],  int8Array[6],  int8Array[7],
                     int8Array[8],  int8Array[9],  int8Array[10], int8Array[11],
                     int8Array[12], int8Array[13], int8Array[14], int8Array[15],
                     int8Array[16], int8Array[17], int8Array[18], int8Array[19],
                     int8Array[20], int8Array[21], int8Array[22], int8Array[23],
                     int8Array[24], int8Array[25], int8Array[26], int8Array[27],
                     int8Array[28], int8Array[29], int8Array[30], int8Array[31])
        var externalForm = AuthorizationExternalForm(bytes: bytes)
        
        // Create the authorization
        return try AuthorizationError.throwIfFailure { authorization in
            AuthorizationCreateFromExternalForm(&externalForm, &authorization)
        }
    }
    
    /// Frees the underlying [`AuthorizationRef`](https://developer.apple.com/documentation/security/authorizationref).
    deinit {
        AuthorizationFree(self.authorizationRef, AuthorizationFlags())
    }
    
    /// Encodes this instance.
    ///
    /// - Parameter encoder: Encoder to encode this instance into.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(try self.serialize())
    }
    
    private func serialize() throws -> Data {
        // Convert authorization into external form
        var externalForm = AuthorizationExternalForm()
        try AuthorizationError.throwIfFailure {
            AuthorizationMakeExternalForm(self.authorizationRef, &externalForm)
        }
        
        // Turn external form into a Data instance
        let bytes = externalForm.bytes
        let int8array = [bytes.0,  bytes.1,  bytes.2,  bytes.3,  bytes.4,  bytes.5,  bytes.6,  bytes.7,
                         bytes.8,  bytes.9,  bytes.10, bytes.11, bytes.12, bytes.13, bytes.14, bytes.15,
                         bytes.16, bytes.17, bytes.18, bytes.19, bytes.20, bytes.21, bytes.22, bytes.23,
                         bytes.24, bytes.25, bytes.26, bytes.27, bytes.28, bytes.29, bytes.30, bytes.31]
        let uint8Array = int8array.map { UInt8(bitPattern: $0) }
        
        return Data(uint8Array)
    }
    
    /// Frees the memory associated with the authorization reference, removing all shared and non-shared authorizations.
    ///
    /// After this is called, most other functions will throw an error if called.
    public func destroyRights() throws {
        try AuthorizationError.throwIfFailure {
            AuthorizationFree(self.authorizationRef, AuthorizationFlags([.destroyRights]))
        }
    }
    
    /// Authorizes and preauthorizes rights synchronously.
    ///
    /// There are three main reasons to use this function:
    /// 1. To preauthorize rights by including ``AuthorizationOption/preAuthorize``, ``AuthorizationOption/interactionAllowed``, and
    ///   ``AuthorizationOption/extendRights``  as authorization `options`. Preauthorization is most useful when a right has a zero timeout. For
    ///   example, you can preauthorize in the application and if it succeeds, call the helper tool and request authorization. This eliminates calling the helper tool if
    ///   the Security Server cannot later authorize the specified rights.
    /// 2.  To authorize rights before performing a privileged operation by specifying
    ///   ``AuthorizationOption/interactionAllowed`` and ``AuthorizationOption/extendRights`` as `options`.
    /// 3. To authorize partial rights. By specifying  ``AuthorizationOption/partialRights`` ,
    ///   ``AuthorizationOption/interactionAllowed``, and ``AuthorizationOption/extendRights`` values as `options`,
    ///   the Security Server grants all rights it can authorize.  The array of ``AuthorizationRight`` instances returned contains all the granted rights.
    ///
    /// > Warning: If you do not include ``AuthorizationOption/partialRights`` as an option and the Security Server denies at least one right, then
    ///         this function will throw ``AuthorizationError/denied``.
    ///
    /// If you do **not** include ``AuthorizationOption/interactionAllowed`` as an option and the Security Server requires user interaction,
    /// then this function will throw ``AuthorizationError/interactionNotAllowed``.
    ///
    /// If you **do** include ``AuthorizationOption/interactionAllowed`` as an option and the user cancels the authentication process, then this
    /// function will throw ``AuthorizationError/canceled``.
    ///
    /// - Parameters:
    ///   - rights: Set of authorization rights. These rights must be defined in the Policy Database. If the application requires no rights at this time,
    ///             pass an empty set.
    ///   - environment: Environment entries used when authorizing or preauthorizing rights.  The entries passed in are not stored; they are only used during
    ///                  authorization. If there is no need to modify the environment, pass an empty set.
    ///   - options: A set specifying authorization options. You can specify the following options:
    ///     - Pass an empty set if no options are necessary.
    ///     - Include ``AuthorizationOption/extendRights`` to request rights. You can also include
    ///       ``AuthorizationOption/interactionAllowed`` to allow user interaction.
    ///     - Include ``AuthorizationOption/partialRights`` and ``AuthorizationOption/extendRights``  to request partial rights.
    ///       You can also include ``AuthorizationOption/interactionAllowed`` to allow user interaction.
    ///     - Include ``AuthorizationOption/preAuthorize`` and ``AuthorizationOption/extendRights`` to preauthorize rights.
    ///     - Include ``AuthorizationOption/destroyRights`` to prevent the Security Server from preserving the rights obtained during this call.
    /// - Returns: The rights granted by the Security Server. If you include ``AuthorizationOption/preAuthorize`` in the `options` set, this
    ///            function returns all the requested rights, including those not granted, but the entries that could not be preauthorized will return `true` for
    ///            ``AuthorizationRight/cannotPreAuthorize``.
    public func requestRights(_ rights: Set<AuthorizationRight>,
                              environment: Set<AuthorizationEnvironmentEntry>,
                              options: Set<AuthorizationOption>) throws -> [AuthorizationRight] {
        return try rights.withUnsafePointer { rightsPointer in
            return try environment.withUnsafePointer { environmentPointer in
                let authorizedRights: UnsafeMutablePointer<AuthorizationItemSet> =
                                                            try AuthorizationError.throwIfFailure { authorizedRights in
                    AuthorizationCopyRights(self.authorizationRef,
                                            rightsPointer,
                                            environmentPointer,
                                            options.asAuthorizationFlags(),
                                            &authorizedRights)
                }
                defer { AuthorizationFreeItemSet(authorizedRights) }
                
                return authorizedRights.pointee.wrap(type: AuthorizationRight.self)
            }
        }
    }
    
    /// Authorizes and preauthorizes rights asynchronously.
    ///
    /// See the discussion for  ``Authorization/requestRights(_:environment:options:)`` This function behaves similarly, except that it
    /// performs its operations asynchronously and calls the `callback` upon completion.
    ///
    /// - Parameters:
    ///   - rights: Set of authorization rights. These rights must be defined in the Policy Database. If the application requires no rights at this time,
    ///             pass an empty set.
    ///   - environment: Environment entries used when authorizing or preauthorizing rights.  The entries passed in are not stored; they are only used during
    ///                  authorization. If there is no need to modify the environment, pass an empty set.
    ///   - options: A set specifying authorization options. You can specify the following options:
    ///     - Pass an empty set if no options are necessary.
    ///     - Include ``AuthorizationOption/extendRights`` to request rights. You can also include
    ///       ``AuthorizationOption/interactionAllowed`` to allow user interaction.
    ///     - Include ``AuthorizationOption/partialRights`` and ``AuthorizationOption/extendRights``  to request partial rights.
    ///       You can also include ``AuthorizationOption/interactionAllowed`` to allow user interaction.
    ///     - Include ``AuthorizationOption/preAuthorize`` and ``AuthorizationOption/extendRights`` to preauthorize rights.
    ///     - Include ``AuthorizationOption/destroyRights`` to prevent the Security Server from preserving the rights obtained during this call.
    ///   - callback: A callback that you provide for the function to call when it finishes asynchronously.
    public func requestRightsAsync(_ rights: Set<AuthorizationRight>,
                                   environment: Set<AuthorizationEnvironmentEntry>,
                                   options: Set<AuthorizationOption>,
                                   callback: @escaping ((Result<[AuthorizationRight], AuthorizationError>) -> Void)) {
        let legacyCallback = { (status: OSStatus, rightsPointer: UnsafeMutablePointer<AuthorizationRights>?) in
            let result: Result<[AuthorizationRight], AuthorizationError>
            if status == errAuthorizationSuccess, let rightsPointer = rightsPointer {
                result = .success(rightsPointer.pointee.wrap(type: AuthorizationRight.self))
            } else {
                result = .failure(AuthorizationError.fromResult(status))
            }
            callback(result)
        }
        
        rights.withUnsafePointer { rightsPointer in
            environment.withUnsafePointer { environmentPointer in
                AuthorizationCopyRightsAsync(self.authorizationRef,
                                             rightsPointer,
                                             environmentPointer,
                                             options.asAuthorizationFlags(),
                                             legacyCallback)
            }
        }
    }
    
    /// Retrieves supporting information such as the user name gathered during evaluation of authorization.
    ///
    /// Information provided via
    /// [`SetContextValue`](https://developer.apple.com/documentation/security/authorizationcallbacks/1543148-setcontextvalue)
    /// from any authorization plug-ins may be made returned.
    ///
    /// - Parameters:
    ///   - tag: If provided, specifies the type of information the Security Server should return. If not provided, all available information will be returned.
    /// - Returns: Dictionary of side-band authorization information. While the values can be anything, in practice they're often UTF8 encoded C strings.
    public func retrieveInfo(tag: String? = nil) throws -> [String : ContiguousArray<CChar>] {
        let copyInfoClosure = { (tagPointer: UnsafePointer<Int8>?) -> [AuthorizationInfo] in
            let info: UnsafeMutablePointer<AuthorizationItemSet> = try AuthorizationError.throwIfFailure { info in
                AuthorizationCopyInfo(self.authorizationRef, tagPointer, &info)
            }
            defer { AuthorizationFreeItemSet(info) }
            
            return info.pointee.wrap(type: AuthorizationInfo.self)
        }
        
        let info: [AuthorizationInfo]
        if let tag = tag {
            info = try tag.withCString(copyInfoClosure)
        } else {
            info = try copyInfoClosure(nil)
        }
        let infoDictionary = Dictionary(uniqueKeysWithValues: info.map{ ($0.name, $0.value ) })
        
        return infoDictionary
    }
}
