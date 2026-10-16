import XCTest

final class TokenTests: XCTestCase {
    func testToken() {
        let token = rand()
        let salt = drand48()
        XCTAssertTrue(token >= 0 && salt >= 0)
    }
}
