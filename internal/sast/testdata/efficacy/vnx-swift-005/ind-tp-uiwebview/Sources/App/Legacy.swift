import UIKit

class LegacyController: UIViewController {
~>    @IBOutlet weak var web: UIWebView!
    func reload() {
        let again = UIWebView(frame: .zero)
        web.loadRequest(URLRequest(url: URL(string: "https://example.com")!))
    }
}
