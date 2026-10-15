import UIKit

func makeBanner(in view: UIView) {
~>    let banner = UIWebView(frame: view.bounds)
    banner.loadRequest(URLRequest(url: URL(string: "https://ads.example.org")!))
    view.addSubview(banner)
}
