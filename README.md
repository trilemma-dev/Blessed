Leverage [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless) functionality
with just one function call:

```swift
let message = "Example App needs your permission to do thingamajig."
let icon = Bundle.main.url(forResource: "bless", withExtension: "png")
try PrivilegedHelperManager.shared.authorizeAndBless(message: message, icon: icon)
```

Both the `message` and `icon` parameters are optional. Defaults will be provided by macOS if they are not specified.

On macOS 10.15 and later this functionality is also available as an `async` variant which will not block while waiting
for a user to grant (or decline) authorization.

## Errors
One of the most challenging aspects of using `SMJobBless` is that when it fails, it can be very hard to determine _why_.
To assist your debugging of such situations, this package throws a `BlessError` which provides a detailed explanation
for each bless requirement which was not met. For example:
```
[BlessError] This application did not meet any of the bundled helper tool's code signing requirements:
and {false}
|--and {false}
|  |--and {false}
|  |  |--identifier "com.example.SwiftClient" {false}¹
|  |  \--anchor apple generic {true}
|  \--certificate leaf[subject.CN] = "Apple Development: Johnny Appleseed (U33GZ847WW)" {false}²
\--certificate 1[field.1.2.840.113635.100.6.2.1] {true}

Constraints not satisfied:
1. Identifiers did not match. Expected: com.example.SwiftClient Actual: com.example.SwiftJobBlessClient
2. Apple Development: Tim Apple (U33ZG847WW) is not equal to expected value Apple Development: Johnny Appleseed (U33GZ847WW)

Underlying error: Error Domain=CFErrorDomainLaunchd Code=4 "(null)"
```

To see a runnable sample app using this framework, check out
[SwiftAuthorizationSample](https://github.com/trilemma-dev/SwiftAuthorizationSample) which also makes use of
[SecureXPC](https://github.com/trilemma-dev/SecureXPC/) for secure interprocess communication.

[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Ftrilemma-dev%2FBlessed%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/trilemma-dev/Blessed)

## macOS 13 and later
If your minimum deployment target is macOS 13 or later, Apple recommends you use
[SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice) instead to register a
Launch Daemon.

## Advanced Use Cases
If you have a need to seperately obtain authorization and then bless, you'll want to make direct use of the
[Authorized](https://github.com/trilemma-dev/Authorized) package (which is one of Blessed's depedendencies)to create an
`Authorization` instance and then pass it to the ``PrivilegedHelperManager/bless(label:authorization:)`` function.

## Sandboxing
Blessing is *not* available to sandboxed processes because of privilege escalation. If you need to determine at run time
if your process is sandboxed, this package adds a property to `ProcessInfo`: `ProcessInfo.processInfo.isSandboxed`.
