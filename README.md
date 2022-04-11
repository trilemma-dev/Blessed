Leverage [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless) functionality
with just one function call:

```swift
let message = "Example App needs your permission to do thingamajig."
let icon = Bundle.main.url(forResource: "bless", withExtension: "png")
try LaunchdManager.authorizeAndBless(message: message, icon: icon)
```

Both the `message` and `icon` parameters are optional. Defaults will be provided by macOS if they are not specified.

On macOS 10.15 and later this functionality is also available as an `async` variant which will not block while waiting
for a user to grant (or decline) authorization. 

To see a runnable sample app using this framework, check out
[SwiftAuthorizationSample](https://github.com/trilemma-dev/SwiftAuthorizationSample).

[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Ftrilemma-dev%2FBlessed%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/trilemma-dev/Blessed)

## Overview
Beyond making it easy to bless a helper tool, Blessed provides a complete Swift implementation of the non-deprecated
portions of macOS's [Authorization Services](https://developer.apple.com/documentation/security/authorization_services)
and [Service Management](https://developer.apple.com/documentation/servicemanagement)
frameworks. At a high level this framework exposes three closely related capabilities:
1. Requesting a user grant permission for one or more rights via macOS's Security Server
2. Defining custom rights in the Policy Database
3. Using `launchd` to install helper tool executables which will run with root privileges

For completeness the Service Management capability to enable and disable login items via `launchd` is also included; see
`LaunchdManager.enableLoginItem(forBundleIdentifier:)` and `LaunchdManager.disableLoginItem(forBundleIdentifier:)`.

## Authorization
In some more advanced circumstances you may to want directly interact with macOS's Security Server via the
`Authorization` class.

If you only need to check if a user can perform an operation, use `checkRights(_:environment:options:)` without needing
to create an `Authorization` instance.

Otherwise you'll typically want to initialize an instance via `init()` and then subsequently request rights with
`requestRights(_:environment:options:)` or  `requestRightsAsync(_:environment:options:callback:)`.

## Defining Custom Rights
macOS's authorization system is built around the concept of rights. The Policy Database contains definitions for all of
the rights on the system and your application can add its own.

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

The above example creates a right called "com.example.MyApp.special-action" which requires that the user authenticate as
an admin. How exactly the user does so is up to macOS; your application does not concern itself with this. (At the time
of this documentation being written this means the user needing to type in a password, but in the future Apple could for
example update their implementation of the `authenticateAsAdmin` rule to use Touch ID.) When the user is asked to
authenticate they will see the message "MyApp would like to perform a special action."

There are several optional parameters not used in this example, see the documentation for details.

If you need to create a rule which is not solely composed of already existing rules, you must create an authorization
plug-in, which is not covered by this framework. See
[Using Authorization Plug-ins](https://developer.apple.com/documentation/security/authorization_plug-ins/using_authorization_plug-ins)
for more information.

## Sandboxing
Most of this framework is *not* available to sandboxed apps because of privilege escalation.

The exceptions to this are:
 - reading or existence checking a right definition in the Policy Database
 - enabling or disabling a login item

If you need to determine at run time if your app is sandboxed, this framework exposes an extension on `NSApplication`:
```swift
let sandboxed = try NSApplication.shared.isSandboxed()
```
