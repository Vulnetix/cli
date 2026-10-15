import WebKit

final class NavigationLogger: NSObject, WKNavigationDelegate {
    let webView = WKWebView()

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        print("loaded \(webView.url?.absoluteString ?? "")")
    }
}
