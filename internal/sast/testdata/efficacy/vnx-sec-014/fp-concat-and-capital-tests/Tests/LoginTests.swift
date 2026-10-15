import XCTest

final class LoginTests: XCTestCase {
    func testRejectsBadCredential() {
        let password = "N0t-the-right-one"
        XCTAssertFalse(Auth.login(user: "invalid", password: password))
    }
}
