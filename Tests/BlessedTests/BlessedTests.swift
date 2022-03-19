import XCTest
@testable import Blessed

final class BlessedTests: XCTestCase {
    func testAuthorizationInit() throws {
        try XCTAssertNotNil(Authorization())
    }
}
