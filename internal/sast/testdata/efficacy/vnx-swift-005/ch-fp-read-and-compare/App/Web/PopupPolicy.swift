import WebKit

struct PopupPolicy {
    func apply(to config: WKWebViewConfiguration, trusted: Bool) {
        config.preferences.javaScriptCanOpenWindowsAutomatically = false
        if config.preferences.javaScriptCanOpenWindowsAutomatically == true {
            print("popups on")
        }
        let allowed = config.preferences.javaScriptCanOpenWindowsAutomatically
        _ = allowed
    }
}
