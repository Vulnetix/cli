import WebKit

func makeWeb() -> WKWebView {
    let prefs = WKPreferences()
~>    prefs.javaScriptCanOpenWindowsAutomatically = true
    let cfg = WKWebViewConfiguration()
    cfg.preferences = prefs
    return WKWebView(frame: .zero, configuration: cfg)
}
