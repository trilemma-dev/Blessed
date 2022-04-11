//
//  AuthorizationElements.swift
//  Blessed
//
//  Created by Josh Kaplan on 2021-10-21
//

import Foundation

/// Corresponds to the C struct `AuthorizationItem` and an array of these corresponds to C struct`AuthorizationItemSet`.
internal protocol AuthorizationElement {
    var name: String { get }
    var value: ContiguousArray<CChar> { get }
    var flags: UInt32 { get }
    
    init(name: String, value: ContiguousArray<CChar>, flags: UInt32)
}

internal extension AuthorizationElement {
    /// Provides this item as an `UnsafePointer<AuthorizationItemSet>` to the closure.
    ///
    /// A closure must be used to because the memory pointers referenced are only valid within the closure.
    func withUnsafePointer<Result>(_ body: (UnsafePointer<AuthorizationItemSet>) throws -> Result) rethrows -> Result {
        return try self.name.withCString { namePointer in
            var mutableValue = value
            return try mutableValue.withUnsafeMutableBufferPointer { valuePointer in
                let item = AuthorizationItem(name: namePointer,
                                             valueLength: value.count,
                                             value: value.count == 0 ? nil : valuePointer.baseAddress,
                                             flags: self.flags)
                var items = [item]
                return try items.withUnsafeMutableBufferPointer { buffer in
                    var itemSet = AuthorizationItemSet(count: 1, items: buffer.baseAddress)
                    
                    return try body(&itemSet)
                }
            }
        }
    }
}

/// An authorization right.
///
/// The existence of a right instance does not mean it is defined in the Policy Database. To determine whether a right has a definition (meaning it exists) call
/// ``AuthorizationRight/isDefined()``. If this right was returned from
/// ``Authorization/requestRights(_:environment:options:)-5wtuy`` or an asynchronous equivalent then this right was defined at the moment
/// in time it was returned.
///
/// ## Topics
/// ### Initializers
/// - ``init(name:)``
/// ### launchd Rights
/// - ``blessPrivilegedHelper``
/// - ``modifySystemsDaemon``
/// ### Policy Database
/// - ``isDefined()``
/// - ``retrieveDefinition()``
/// - ``createOrUpdateDefinition(rules:authorization:descriptionKey:bundle:localeTableName:comment:)``
/// - ``removeDefinition(authorization:)``
public struct AuthorizationRight: AuthorizationElement, Hashable {
    /// The name of this authorization right.
    public let name: String
    
    /// While in theory this value can be set, in practice it appears it never actually is.
    ///
    /// The only documentation which mentions it is for `kAuthorizationRightExecute` which says it will be used "in the future", but that future never
    /// came to pass as this is effectively deprecated because the `AuthorizationExecuteWithPrivileges` function it is meant to be used with has been
    /// deprecated since 10.8.
    internal let value: ContiguousArray<CChar>
    
    /// Flags returned when calling AuthorizationCopyRights. As of macOS 12, the only valid value is `kAuthorizationFlagCanNotPreAuthorize`.
    internal let flags: UInt32
    
    internal init(name: String, value: ContiguousArray<CChar>, flags: UInt32) {
        self.name = name
        self.value = value
        self.flags = flags
    }
    
    /// Creates an authorization right with this name.
    ///
    /// Creating an authorization right does not mean it is defined in the Policy Database.
    ///
    /// - Parameter name: The name of this right.
    public init(name: String) {
        self.name = name
        self.value = ContiguousArray<CChar>()
        self.flags = 0
    }
    
    /// If a requested right cannot be preauthorized.
    ///
    /// This only has defined behavior when the right was returned from  ``Authorization/requestRights(_:environment:options:)-5wtuy`` or
    /// asynchronous equivalent. Otherwise this property's value is undefined.
    public var cannotPreAuthorize: Bool {
        return self.flags == kAuthorizationFlagCanNotPreAuthorize
    }
}

/// Environment configuration options when requesting authorization.
///
/// Static convenience initializers are provided to create this as one of the environment entry types defined in the Security framework.
///
/// ## Topics
/// ### Convenience Initializers
/// - ``forUsername(_:)``
/// - ``forPassword(_:)``
/// - ``forShared()``
/// - ``forPrompt(message:)``
/// - ``forIcon(_:)``
public struct AuthorizationEnvironmentEntry: AuthorizationElement, Hashable {
    /// The name of this entry.
    internal let name: String
    /// The value associated with this entry.
    ///
    /// Typically this is a UTF8 encoded C string.
    internal let value: ContiguousArray<CChar>
    /// In practice this never appears to be used and so is not exposed.
    internal let flags: UInt32
    
    internal init(name: String, value: ContiguousArray<CChar>, flags: UInt32) {
        self.name = name
        self.value = value
        self.flags = flags
    }
    
    /// Initialize an environment entry.
    ///
    /// - Parameters:
    ///   - name: The name of this entry.
    ///   - value: The value associated with this entry, in practice this is typically a UTF8 encoded C string.
    public init(name: String, value: ContiguousArray<CChar>) {
        self.name = name
        self.value = value
        self.flags = 0
    }
    
    /// Initialize an environment entry.
    ///
    /// - Parameters:
    ///   - name: The name of this entry.
    ///   - value: The value associated with this entry.
    public init(name: String, value: String) {
        self = AuthorizationEnvironmentEntry(name: name, value: value.utf8CString)
    }
    
    /// An `AuthorizationEnvironmentEntry` instance for specifying the provided username.
    ///
    /// If part of the environment along with ``forPassword(_:)`` then ``forShared()`` should also be included.
    /// - Parameter username: The username to be used.
    /// - Returns: The environment entry.
    public static func forUsername(_ username: String) -> AuthorizationEnvironmentEntry {
        return AuthorizationEnvironmentEntry(name: kAuthorizationEnvironmentUsername, value: username)
    }
    
    /// An `AuthorizationEnvironmentEntry` instance for specifying the provided password.
    ///
    /// If part of the environment along with ``forUsername(_:)`` then ``forShared()`` should also be included.
    /// - Parameter password: The actual password data.
    /// - Returns: The environment entry.
    public static func forPassword(_ password: String) -> AuthorizationEnvironmentEntry {
        return AuthorizationEnvironmentEntry(name: kAuthorizationEnvironmentPassword, value: password)
    }
    
    /// An `AuthorizationEnvironmentEntry` instance that should be part of the enviroment when ``forUsername(_:)`` and
    /// ``forPassword(_:)`` are included.
    ///
    /// Adding this entry to the environment will cause the username/password to be added to the pool of the calling applications session.  This means that
    /// further calls by other applications in this session will automatically have this credential availible to them.
    /// - Returns: The environment entry.
    public static func forShared() -> AuthorizationEnvironmentEntry {
        return AuthorizationEnvironmentEntry(name: kAuthorizationEnvironmentShared, value: [])
    }
    
    /// An `AuthorizationEnvironmentEntry` instance for providing additional text specific to the invocation.
    ///
    /// - Parameter message: A localized string.
    /// - Returns: The environment entry.
    public static func forPrompt(message: String) -> AuthorizationEnvironmentEntry {
        return AuthorizationEnvironmentEntry(name: kAuthorizationEnvironmentPrompt, value: message)
    }
    
    /// An `AuthorizationEnvironmentEntry` instance for specifying an alternative icon to be used.
    /// - Parameter icon: A filepath to an image [`NSImage`](https://developer.apple.com/documentation/appkit/nsimage) supports.
    /// - Returns: The environment entry.
    public static func forIcon(_ icon: URL) -> AuthorizationEnvironmentEntry {
        return AuthorizationEnvironmentEntry(name: kAuthorizationEnvironmentIcon, value: icon.absoluteString)
    }
}

/// Information about an ``Authorization``.
///
/// Package internal struct used by ``Authorization/retrieveInfo(tag:)``.
internal struct AuthorizationInfo: AuthorizationElement {
    /// The name of this info.
    let name: String
    /// The value asociated with this info.
    ///
    /// The specific format of this value can differ for each `AuthorizationInfo` instance, but in practice is commonly a UTF8 encoded C string.
    let value: ContiguousArray<CChar>
    /// In practice this never appears to be used.
    let flags: UInt32
    
    init(name: String, value: ContiguousArray<CChar>, flags: UInt32) {
        self.name = name
        self.value = value
        self.flags = flags
    }
}

internal extension Set where Element: AuthorizationElement {
    func withUnsafePointer<Result>(_ body: (UnsafePointer<AuthorizationItemSet>) throws -> Result) rethrows -> Result {
        try Set<Element>.convertRecursively(wrappers: Array<Element>(self), items: [], body: body)
    }
    
    /// This inner function uses an **array** of `AuthorizationElement` instances because AuthorizationElement itself does not conform to Hashable and
    /// so it is not possible to create a set of them. Concrete implementations of `AuthorizationElement` do implement Hashable, hence why it is possible
    /// for this extension of Set to be usable.
    private static func convertRecursively<Result>(wrappers: [AuthorizationElement],
                                                   items: [AuthorizationItem],
                                                   body: (UnsafePointer<AuthorizationItemSet>) throws -> Result)
                                                   rethrows -> Result {
        // One or more wrappers to be converted
        if let wrapper = wrappers.first {
            var remainingWrappers = wrappers
            remainingWrappers.removeFirst()
            
            return try wrapper.name.withCString { namePointer in
                var mutableValue = wrapper.value
                return try mutableValue.withUnsafeMutableBufferPointer { valuePointer in
                    let item = AuthorizationItem(name: namePointer,
                                                 valueLength: wrapper.value.count,
                                                 value: valuePointer.baseAddress,
                                                 flags: wrapper.flags)
                    var itemsUnwrapped = items
                    itemsUnwrapped.append(item)
                    
                    // Recurse
                    return try convertRecursively(wrappers: remainingWrappers, items: itemsUnwrapped, body: body)
                }
            }
        }
        // Reached the base case, create the AuthorizationItemSet with all of the converted items
        else {
            var mutableItems = items
            let count = UInt32(items.count)
            return try mutableItems.withUnsafeMutableBufferPointer { buffer in
                var itemSet = AuthorizationItemSet(count: count, items: buffer.baseAddress)
                
                return try body(&itemSet)
            }
        }
    }
}

internal extension AuthorizationItem {
    func wrap<T>(type: T.Type) -> T where T:AuthorizationElement {
        let name = String(cString: self.name)
        var value = ContiguousArray<CChar>()
        if self.valueLength > 0, let valuePointer = self.value {
            for offset in 0...self.valueLength { // iterate inclusive of length to get NULL termination
                let offsetPointer = valuePointer + offset
                let char = offsetPointer.load(as: CChar.self)
                value.append(char)
            }
        }
        
        return T(name: name, value: value, flags: self.flags)
    }
}

internal extension AuthorizationItemSet {
    func wrap<T>(type: T.Type) -> [T] where T:AuthorizationElement {
        var items = [T]()
        for index in 0..<Int(self.count) {
            if let item = self.items?.advanced(by: index).pointee {
                items.append(item.wrap(type: type))
            }
        }
        
        return items
    }
}
