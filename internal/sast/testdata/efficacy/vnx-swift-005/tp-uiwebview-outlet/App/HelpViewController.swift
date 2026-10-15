import UIKit

class HelpViewController: UIViewController, UIWebViewDelegate {
~>    @IBOutlet var webView: UIWebView!

    override func viewDidLoad() {
        super.viewDidLoad()
        webView.delegate = self
        webView.loadHTMLString(helpHTML, baseURL: nil)
    }

    func webView(_ webView: UIWebView, shouldStartLoadWith request: URLRequest, navigationType: UIWebView.NavigationType) -> Bool {
        return true
    }
}
