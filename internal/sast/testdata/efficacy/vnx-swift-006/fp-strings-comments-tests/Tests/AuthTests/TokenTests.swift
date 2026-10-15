import XCTest

final class TokenTests: XCTestCase {
    func testToken() {
        srand48(1)
        let token = drand48()
        XCTAssertGreaterThan(token, 0)
    }
}
