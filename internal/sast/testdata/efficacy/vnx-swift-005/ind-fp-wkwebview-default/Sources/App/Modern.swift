import WebKit

final class ModernBrowser: NSObject, WKUIDelegate {
    lazy var web: WKWebView = {
        let cfg = WKWebViewConfiguration()
        cfg.preferences.javaScriptEnabled = true
        cfg.preferences.javaScriptCanOpenWindowsAutomatically = false
        let w = WKWebView(frame: .zero, configuration: cfg)
        w.uiDelegate = self
        return w
    }()
    func isPopupAllowed() -> Bool {
        return web.configuration.preferences.javaScriptCanOpenWindowsAutomatically
    }
}
