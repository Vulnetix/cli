import WebKit

enum BrowserFactory {
    static func make() -> WKWebView {
        let prefs = WKPreferences()
~>        prefs.javaScriptCanOpenWindowsAutomatically=true
        let config = WKWebViewConfiguration()
        config.preferences = prefs
        let web = WKWebView(frame: .zero, configuration: config)
~>        web.configuration.preferences.javaScriptCanOpenWindowsAutomatically = true // popups for SSO
        return web
    }
}
