---
title: "VNX-ANDROID-002 – Android WebView JavaScript Enabled"
description: "Detects a JavaScript-enabled Android WebView (Java/Kotlin) that loads a URL or HTML from an Intent, deep link, Fragment arguments, external storage or a cleartext http:// address, an evaluateJavascript call built from such a value, a JavaScript bridge added in such a file, and file:// pages given universal or file access."
category: sast
---

## Overview

This rule reports Android WebViews (Java and Kotlin) that run script an attacker controls. Enabling JavaScript is not a finding on its own. The rule reports a `loadUrl`, `loadData`, `loadDataWithBaseURL` or `postUrl` call in a file that enables JavaScript when the URL or HTML comes from the launching Intent or a deep link (`getIntent()`, `getStringExtra`, `getData`, `getQueryParameter`, Fragment arguments), from external storage, or is a cleartext `http://` address, either directly or through a variable assigned from such a source up to 15 lines above. It also reports `addJavascriptInterface` in a file with such a load, and `setAllowUniversalAccessFromFileURLs(true)` / `setAllowFileAccessFromFileURLs(true)`. A URL checked between the read and the load (`startsWith`, host or scheme comparison, an allow-list or validator) is not reported, nor are `https://` and `file:///android_asset/` literals, `http://localhost`, comments and strings. Flows through other methods or files are not followed. These patterns are captured by CWE-79 (Improper Neutralization of Input During Web Page Generation).

**Severity:** High | **CWE:** [CWE-79 – Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html)

## Why This Matters

A WebView with JavaScript enabled and a registered `JavascriptInterface` gives any JavaScript running in that view direct access to the annotated Java methods. If the WebView ever loads attacker-controlled content — a redirected URL, an injected ad, a compromised CDN response — the attacker can call those Java methods and execute arbitrary native code on the device. On Android < 4.2, all public methods of any registered object were callable; from 4.2 onward only methods annotated with `@JavascriptInterface` are exposed, but the risk remains high.

Enabling universal file access (`setAllowUniversalAccessFromFileURLs`) allows a `file://` URL to read any file the app has access to, enabling data theft across origins. Several banking apps have been attacked via this vector, where malicious deep-link payloads loaded a crafted `file://` URL that exfiltrated the app's database. CAPEC-86 documents this class of DOM-based XSS attack directly.

## What Gets Flagged

```java
// FLAGGED: a URL from the launching Intent loaded into a JavaScript-enabled WebView
webView.getSettings().setJavaScriptEnabled(true);
String target = getIntent().getStringExtra("url");
webView.loadUrl(target);

// FLAGGED: a statement file on external storage
webView.loadUrl("file://" + Environment.getExternalStorageDirectory() + "/statement.html");

// FLAGGED: file:// pages may read any origin
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
```

```kotlin
// FLAGGED: a deep-link parameter
settings.javaScriptEnabled = true
val page = intent.data?.getQueryParameter("page")
webView.loadUrl(page!!)
```

Not flagged: `setJavaScriptEnabled(true)` with only `https://` or `file:///android_asset/` loads, or an intent URL checked with `Uri.parse(u).host == "help.example.com"` before the load.

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
