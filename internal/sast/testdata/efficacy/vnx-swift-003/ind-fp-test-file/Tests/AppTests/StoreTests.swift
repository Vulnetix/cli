import XCTest

final class StoreTests: XCTestCase {
    func testSave() {
        UserDefaults.standard.set(password, forKey: "password")
        UserDefaults.standard.set(authToken, forKey: "authToken")
    }
}
