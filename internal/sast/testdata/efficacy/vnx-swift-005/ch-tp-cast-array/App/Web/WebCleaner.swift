import UIKit

final class WebCleaner {
    func purge(in root: UIView) {
~>        for case let web as UIWebView in root.subviews {
            web.stopLoading()
        }
    }
}
