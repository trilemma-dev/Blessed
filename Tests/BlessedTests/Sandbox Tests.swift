//
//  Sandbox Tests.swift
//  Blessed
//
//  Created by Josh Kaplan on 2022-05-12
//

import XCTest
import Blessed

final class SandboxTests: XCTestCase {
    
    func testIsSandboxed() {
        XCTAssertFalse(ProcessInfo.processInfo.isSandboxed)
    }
}
