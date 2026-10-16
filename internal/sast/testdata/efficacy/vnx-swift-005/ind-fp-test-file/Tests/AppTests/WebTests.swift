import XCTest
import WebKit

final class WebTests: XCTestCase {
    func testOpen() {
        let p = WKPreferences()
        p.javaScriptCanOpenWindowsAutomatically = true
        let w = UIWebView()
        XCTAssertNotNil(w)
    }
}
