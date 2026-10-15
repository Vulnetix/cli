import WebKit

/// Replaces the old UIWebView screen with WKWebView.
final class UIWebViewMigrationController: UIViewController {
    let legacyClass: AnyClass? = NSClassFromString("UIWebView")
    let note = "UIWebView is deprecated"
    let web = WKWebView()
}
