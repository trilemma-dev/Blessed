# ``Blessed``

A Swift friendly implementation of the Authorization Services and Service Management frameworks.

## Overview

A complete Swift implementation of the non-deprecated portions of the 
[Authorization Services](https://developer.apple.com/documentation/security/authorization_services)
and [Service Management](https://developer.apple.com/documentation/servicemanagement)
frameworks is provided along with additional convenience functions. At a high level this framework exposes three closely
related capabilities:
1. Requesting a user grant permission for one or more rights via macOS's Security Server
2. Defining custom rights in the Policy Database
3. Using `launchd` to install executables which will run with root privileges

For completeness the Service Management capability to enable and disable login items via `launchd` is also included; see
``LaunchdManager/enableLoginItem(forBundleIdentifier:)`` and ``LaunchdManager/disableLoginItem(forBundleIdentifier:)``.

## Installing a Root Privileged Executable
Because in practice #1 is so often done in order to perform #3, this framework provides the
``LaunchdManager/authorizeAndBless(message:icon:)`` function which combines both into just one call:
```swift
let message = "Example App needs your permission to do thingamajig."
let icon = Bundle.main.url(forResource: "bless", withExtension: "png")
try LaunchdManager.authorizeAndBless(message: message, icon: icon)
```

Both the `message` and `icon` parameters are optional. Defaults will be provided by macOS if they are not specified.

## Defining Custom Rights
macOS's authorization system is built around the concept of rights. The Policy Database contains definitions for all
of the rights on the system and your application can add its own.

If an application defines its own rights it can then use these to self-restrict functionality. For details on *why* you
might want to do see, consider reading Apple's [Technical Note TN2095: Authorization for Everyone](https://developer.apple.com/library/archive/technotes/tn2095/_index.html#//apple_ref/doc/uid/DTS10003110)
although keep in mind the code samples shown are not applicable if you are using this Swift implementation.

To define a custom right:
```swift
let myCustomRight = AuthorizationRight(name: "com.example.MyApp.special-action")
let description = "MyApp would like to perform a special action."
let rules: Set<AuthorizationRightRule> = [CannedAuthorizationRightRules.authenticateAsAdmin]
try myCustomRight.createOrUpdateDefinition(rules: rules, descriptionKey: description)
```

The above example creates a right called "com.example.MyApp.special-action" which requires that the user authenticate
as an admin. How exactly the user does so is up to macOS; your application does not concern itself with this. (At the
time of this documentation being written this means the user needing to type in a password, but in the future Apple
could for example update their implementation of the `authenticateAsAdmin` rule to use Touch ID.) When the user is asked
to authenticate they will see the message "MyApp would like to perform a special action."

There are several optional parameters not used in this example, see 
``AuthorizationRight/createOrUpdateDefinition(rules:authorization:descriptionKey:bundle:localeTableName:comment:)`` for
details.

If you need to create a rule which is not solely composed of already existing rules, you must create an authorization
plug-in, which is not covered by this framework. See [Using Authorization Plug-ins](https://developer.apple.com/documentation/security/authorization_plug-ins/using_authorization_plug-ins)
for more information.

## Authorization
In some more advanced circumstances you may to want directly interact with macOS's Security Server via the
``Authorization`` class.

If you only need to check if a user can perform an operation, use ``Authorization/checkRights(_:environment:options:)``
without needing to create an `Authorization` instance.

Otherwise you'll typically want to initialize an instance via ``Authorization/init()`` and then subsequently request
rights with ``Authorization/requestRights(_:environment:options:)`` or 
``Authorization/requestRightsAsync(_:environment:options:callback:)``.

> Tip: `Authorization` conforms to [`Codable`](https://developer.apple.com/documentation/swift/codable) and so can be
serialized and deserialized for convenient transference between processes.

Ultimately `Authorization` is a wrapper around 
 [`AuthorizationRef`](https://developer.apple.com/documentation/security/authorizationref) and so if needed this
underlying reference can be accessed via ``Authorization/authorizationRef``. However, please note the lifetime of this
reference is bound to its containing `Authorization` instance.

## Sandboxing
> Warning: Most of this framework is *not* available to sandboxed apps because of privilege escalation.

The exceptions to this are:
 - reading or existence checking a right definition in the Policy Database
 - enable or disabling a login item

If you need to determine at run time if your app is sandboxed, this framework exposes an extension on
[`NSApplication`](https://developer.apple.com/documentation/appkit/nsapplication):
```swift
let sandboxed = try NSApplication.shared.isSandboxed()
```

## Topics

### Authorization

- ``Authorization``
- ``AuthorizationRight``
- ``AuthorizationEnvironmentEntry``
- ``AuthorizationOption``

### Authorization Policy Database

- ``AuthorizationRight``
- ``AuthorizationRightRule``
- ``CannedAuthorizationRightRules``
- ``AuthorizationRightDefinition``
- ``AuthorizationRightDefinitionClass``
- ``AuthorizationMechanism``

### Authorization Errors

- ``AuthorizationError``

### launchd Registration

- ``LaunchdManager``
- ``LaunchdError``
