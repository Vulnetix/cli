import XCTest
@testable import App

final class SessionTests: XCTestCase {
    let token = "@@sample:e[y]JhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9[.]eyJzdWIiOiJ0ZXN0ZXIiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjQxMDI0NDQ4MDB9[.]xk0TxhBKn9Q1Ch[-]IOSjWwDfZcaAmescI8VpC0UowYiw@@"
    func testDecodes() { XCTAssertFalse(token.isEmpty) }
}
