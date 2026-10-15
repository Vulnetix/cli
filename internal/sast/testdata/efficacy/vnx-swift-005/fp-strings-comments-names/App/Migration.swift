import UIKit

// Migrated from UIWebView to WKWebView in 3.2
/// `javaScriptCanOpenWindowsAutomatically = true` is never set here.
struct Migration {
    let note = "UIWebView is deprecated"
    let legacyClass: AnyClass? = NSClassFromString("UIWebView")
    let myUIWebViewReplacement = "WKWebView"
}
