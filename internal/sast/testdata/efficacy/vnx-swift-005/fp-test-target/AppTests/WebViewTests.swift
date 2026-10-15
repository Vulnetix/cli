import XCTest
import WebKit

final class WebViewTests: XCTestCase {
    func testPopupsCanBeEnabled() {
        let prefs = WKPreferences()
        prefs.javaScriptCanOpenWindowsAutomatically = true
        XCTAssertTrue(prefs.javaScriptCanOpenWindowsAutomatically)
        let legacy: UIWebView? = nil
        XCTAssertNil(legacy)
    }
}
