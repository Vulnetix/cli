import WebKit

func safe() {
    let prefs = WKPreferences()
    prefs.javaScriptCanOpenWindowsAutomatically = false
    let current = prefs.javaScriptCanOpenWindowsAutomatically
    print(current)
    let web = WKWebView(frame: .zero)
    // prefs.javaScriptCanOpenWindowsAutomatically = true
    // legacy UIWebView removed
    let s = "UIWebView and javaScriptCanOpenWindowsAutomatically = true"
    print(s, web)
}
