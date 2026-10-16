import XCTest

final class AuthTests: XCTestCase {
    let password = "correct-horse-battery"
    let apiKey = "test-fixture-key-0123456789"
    func testLogin() {
        let client = Client(clientSecret: "fixtureSecretValue99")
        XCTAssertNotNil(client)
    }
}
