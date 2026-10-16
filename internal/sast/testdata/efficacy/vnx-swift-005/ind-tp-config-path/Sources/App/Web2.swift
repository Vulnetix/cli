import WebKit

final class Browser {
    let config = WKWebViewConfiguration()
    init() {
~>        config.preferences.javaScriptCanOpenWindowsAutomatically = true
    }
}
