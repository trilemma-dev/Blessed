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
    ///  [`SMPrivilegedExecutables`](https://developer.apple.com/documentation/bundleresources/information_property_list/smprivilegedexecutables)
    /// dictionary does not contain exactly one entry.
    case invalidExecutablesDictionary
    /// Unable to enable login item.
    case loginItemNotEnabled
    /// Unable to disable login item.
    case loginItemNotDisabled
}
