import XCTest

final class SessionStoreTests: XCTestCase {
    func testMigration() {
        UserDefaults.standard.set("abc", forKey: "accessToken")
        XCTAssertNil(UserDefaults.standard.string(forKey: "password"))
    }
}
