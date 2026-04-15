---
title: "VNX-SWIFT-005 – Swift WKWebView JavaScript Auto-Open-Windows Enabled"
description: "Detects WKPreferences.javaScriptCanOpenWindowsAutomatically set to true and usage of the deprecated UIWebView, both of which introduce cross-site scripting escalation risks in iOS applications."
---

## Overview

This rule flags two related patterns in Swift source files. First, it detects any line that sets `javaScriptCanOpenWindowsAutomatically` to `true` on a `WKPreferences` object, which allows JavaScript executing inside a `WKWebView` to open new windows or tabs without a user gesture. Second, it detects any usage of `UIWebView`, Apple's legacy web view component that has been deprecated since iOS 8 and removed from the App Store submission requirements since April 2020.

Both patterns represent privilege escalation opportunities for JavaScript running inside the web view. When an app loads user-controlled or third-party web content, these settings allow JavaScript to break out of the page's intended interaction model and take actions — such as opening phishing windows or executing navigation redirects — that the user has not initiated.

This maps to [CWE-272: Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html).

**Severity:** Medium | **CWE:** [CWE-272 – Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html)

## Why This Matters

WebView components are among the highest-risk surfaces in mobile applications because they execute arbitrary HTML and JavaScript. When an app renders content from external URLs, user-generated content, or third-party iframes, any cross-site scripting (XSS) vulnerability in that content can be exploited against the native application context. The `javaScriptCanOpenWindowsAutomatically` setting extends what a successful XSS can accomplish: the attacker-controlled script can open additional windows, potentially loading attacker-controlled content in what appears to be the legitimate application interface.

`UIWebView` carries a more significant risk: it shares the JavaScript context across all `UIWebView` instances in the same process and does not support the same-origin policy enforcement or the process isolation that `WKWebView` provides. Malicious content loaded in a `UIWebView` can read cookies and local storage set by other `UIWebView` instances in the same app, including authentication tokens. Apple explicitly deprecated `UIWebView` for security reasons and the App Store now rejects apps that contain it in the binary.

Hybrid applications that expose Swift-JavaScript bridges (using `WKScriptMessageHandler` or `addJavaScriptInterface`) are particularly sensitive to this class of vulnerability because XSS can directly invoke native code.

## What Gets Flagged

```swift
// FLAGGED: JavaScript window opening enabled in WKPreferences
let preferences = WKPreferences()
preferences.javaScriptCanOpenWindowsAutomatically = true  // FLAGGED

// FLAGGED: deprecated UIWebView instantiated
let webView = UIWebView(frame: view.bounds)  // FLAGGED

// FLAGGED: UIWebView referenced in a type annotation
var legacyWebView: UIWebView!  // FLAGGED
```

## Remediation

1. **Set `javaScriptCanOpenWindowsAutomatically` to `false`.** This is the default value; explicitly setting it to `true` is only necessary for specific use cases such as OAuth pop-up flows. If you need pop-up support, implement it using `WKUIDelegate.webView(_:createWebViewWith:for:windowFeatures:)` and validate the target URL before allowing the new window.

   ```swift
   // SAFE: pop-up windows disabled (this is the default)
   let preferences = WKPreferences()
   preferences.javaScriptCanOpenWindowsAutomatically = false

   let config = WKWebViewConfiguration()
   config.preferences = preferences
   let webView = WKWebView(frame: view.bounds, configuration: config)
   ```

2. **Replace all `UIWebView` usage with `WKWebView`.** The migration is straightforward for most use cases.

   ```swift
   // SAFE: WKWebView with a strict content security policy
   import WebKit

   class SecureWebViewController: UIViewController, WKNavigationDelegate {
       var webView: WKWebView!

       override func viewDidLoad() {
           super.viewDidLoad()
           let config = WKWebViewConfiguration()
           let preferences = WKPreferences()
           preferences.javaScriptCanOpenWindowsAutomatically = false
           config.preferences = preferences

           webView = WKWebView(frame: view.bounds, configuration: config)
           webView.navigationDelegate = self
           view.addSubview(webView)
       }

       // Restrict navigation to trusted origins
       func webView(_ webView: WKWebView,
                    decidePolicyFor navigationAction: WKNavigationAction,
                    decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
           guard let host = navigationAction.request.url?.host,
                 host == "trusted.example.com" else {
               decisionHandler(.cancel)
               return
           }
           decisionHandler(.allow)
       }
   }
   ```

3. **Implement a `WKNavigationDelegate` to control all navigations.** Validate the URL scheme and host before allowing any navigation, blocking `javascript:` URLs and unexpected origins.

4. **Set a Content Security Policy (CSP) header on pages your server delivers.** A strict CSP prevents injected scripts from loading external resources or calling `window.open()` even if XSS is present.

5. **Avoid loading untrusted content in `WKWebView` instances that have access to Swift message handlers.** If you must load external URLs, use a separate `WKWebView` with no `WKScriptMessageHandler` registrations.

## References

- [CWE-272: Least Privilege Violation](https://cwe.mitre.org/data/definitions/272.html)
- [OWASP Mobile Security Testing Guide – MSTG-PLATFORM-5 (WebView JavaScript)](https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0075/)
- [Apple – WKWebView](https://developer.apple.com/documentation/webkit/wkwebview)
- [Apple – WKPreferences.javaScriptCanOpenWindowsAutomatically](https://developer.apple.com/documentation/webkit/wkpreferences/1536573-javascriptcanopenwindowsautomati)
- [Apple – Migrating from UIWebView to WKWebView](https://developer.apple.com/news/whats-new/app-store-submission-is-now-required-for-wkwebview/)
- [CAPEC-86: XSS through HTTP Request Headers](https://capec.mitre.org/data/definitions/86.html)
- [MITRE ATT&CK T1059.007 – Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
