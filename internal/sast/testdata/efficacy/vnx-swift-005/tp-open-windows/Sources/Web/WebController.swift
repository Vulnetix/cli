import WebKit

final class WebController: UIViewController {
    var webView: WKWebView!

    override func loadView() {
        let configuration = WKWebViewConfiguration()
~>        configuration.preferences.javaScriptCanOpenWindowsAutomatically = true
        let prefs = WKPreferences()
~>        prefs.javaScriptCanOpenWindowsAutomatically=true
        configuration.preferences = prefs
        webView = WKWebView(frame: .zero, configuration: configuration)
        view = webView
    }
}
