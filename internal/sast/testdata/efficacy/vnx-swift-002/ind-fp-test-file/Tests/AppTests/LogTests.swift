import XCTest

final class LogTests: XCTestCase {
    func testLog() {
        let password = "x"
        print("password is \(password)")
        NSLog("token %@", password)
    }
}
