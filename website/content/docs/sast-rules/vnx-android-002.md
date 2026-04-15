---
title: "VNX-ANDROID-002 – Android WebView JavaScript Enabled"
description: "Detects insecure WebView configuration in Android apps including enabled JavaScript, file access, and addJavascriptInterface calls that expose apps to XSS and remote code execution."
kind: sast
---

## Overview

This rule detects dangerous WebView configuration calls in Android Java code. Enabling JavaScript (`setJavaScriptEnabled(true)`), bridging native Java objects into the WebView (`addJavascriptInterface`), or relaxing file-system access controls (`setAllowFileAccess`, `setAllowUniversalAccessFromFileURLs`, `setAllowFileAccessFromFileURLs`) creates pathways for cross-site scripting (XSS) and remote code execution. These patterns are captured by CWE-79 (Improper Neutralization of Input During Web Page Generation).

**Severity:** High | **CWE:** [CWE-79 – Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html)

## Why This Matters

A WebView with JavaScript enabled and a registered `JavascriptInterface` gives any JavaScript running in that view direct access to the annotated Java methods. If the WebView ever loads attacker-controlled content — a redirected URL, an injected ad, a compromised CDN response — the attacker can call those Java methods and execute arbitrary native code on the device. On Android < 4.2, all public methods of any registered object were callable; from 4.2 onward only methods annotated with `@JavascriptInterface` are exposed, but the risk remains high.

Enabling universal file access (`setAllowUniversalAccessFromFileURLs`) allows a `file://` URL to read any file the app has access to, enabling data theft across origins. Several banking apps have been attacked via this vector, where malicious deep-link payloads loaded a crafted `file://` URL that exfiltrated the app's database. CAPEC-86 documents this class of DOM-based XSS attack directly.

## What Gets Flagged

The rule matches any of the five indicator method calls in any non-minified source file:

```java
// FLAGGED: JavaScript enabled in WebView
webView.getSettings().setJavaScriptEnabled(true);

// FLAGGED: native object bridged into JavaScript context
webView.addJavascriptInterface(new JsBridge(this), "AndroidBridge");

// FLAGGED: file:// access permitted cross-origin
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
```

## Remediation

1. **Disable JavaScript unless you own every page the WebView loads.** If you are building a hybrid app and must enable JavaScript, use a strict Content Security Policy delivered via HTTP headers or injected via `loadDataWithBaseURL`.

   ```java
   // SAFE: JavaScript disabled for content you do not control
   webView.getSettings().setJavaScriptEnabled(false);
   ```

2. **Remove `addJavascriptInterface` from production code.** If a JS-to-native bridge is required, use `WebMessageListener` (API 23+) which scopes the bridge to specific allowed origins, or build the bridge using a safe messaging protocol verified in `shouldOverrideUrlLoading`.

   ```java
   // SAFE: origin-scoped message listener instead of addJavascriptInterface
   webView.addWebMessageListener(
       "AndroidBridge",
       new HashSet<>(Arrays.asList("https://app.example.com")),
       (view, message, sourceOrigin, isMainFrame, replyProxy) -> {
           // handle message from trusted origin only
       }
   );
   ```

3. **Restrict file access.** Call `setAllowFileAccess(false)`, `setAllowFileAccessFromFileURLs(false)`, and `setAllowUniversalAccessFromFileURLs(false)` explicitly. These settings default to disabled on modern API levels but should be set explicitly to prevent regressions.

   ```java
   // SAFE: all file access disabled
   WebSettings settings = webView.getSettings();
   settings.setAllowFileAccess(false);
   settings.setAllowFileAccessFromFileURLs(false);
   settings.setAllowUniversalAccessFromFileURLs(false);
   ```

4. **Validate URLs before loading.** Override `shouldOverrideUrlLoading` and `shouldInterceptRequest` to enforce an allowlist of permitted origins. Reject `file://`, `javascript:`, `data:`, and `intent://` schemes unless explicitly required.

5. **Enable Safe Browsing.** Call `WebView.startSafeBrowsing()` to enable Google Safe Browsing malicious URL detection in the WebView.

## References

- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)
- [CAPEC-86: XSS Through HTTP Request Headers](https://capec.mitre.org/data/definitions/86.html)
- [MITRE ATT&CK T1059.007 – JavaScript](https://attack.mitre.org/techniques/T1059/007/)
- [Android WebView Security – developer.android.com](https://developer.android.com/develop/ui/views/layout/webapps/webview)
- [Android addWebMessageListener API](https://developer.android.com/reference/androidx/webkit/WebViewCompat#addWebMessageListener(android.webkit.WebView,java.lang.String,java.util.Set,androidx.webkit.WebViewCompat.WebMessageListener))
- [OWASP Mobile Security Testing Guide – MSTG-PLATFORM-6](https://mas.owasp.org/MASTG/tests/android/MASVS-PLATFORM/MASTG-TEST-0031/)
- [OWASP Mobile Top 10 – M1: Improper Platform Usage](https://owasp.org/www-project-mobile-top-10/)
