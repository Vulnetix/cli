import WebKit

final class WebController: UIViewController {
    override func loadView() {
        let configuration = WKWebViewConfiguration()
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = false
        let allowPopups = configuration.preferences.javaScriptCanOpenWindowsAutomatically
        if allowPopups == true { print("popups") }
        view = WKWebView(frame: .zero, configuration: configuration)
    }
}
