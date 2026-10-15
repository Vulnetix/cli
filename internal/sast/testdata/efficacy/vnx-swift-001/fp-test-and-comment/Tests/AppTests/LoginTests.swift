import XCTest
@testable import App

final class LoginTests: XCTestCase {
    func testLogin() {
        let password = "hunter2hunter2"
        let apiKey = "@@sample:k[3]Jd[9]sL[q]02[M]Zp[X]a7[V]t4[c]@@"
        XCTAssertTrue(Login(password: password, apiKey: apiKey).isValid)
    }
}
