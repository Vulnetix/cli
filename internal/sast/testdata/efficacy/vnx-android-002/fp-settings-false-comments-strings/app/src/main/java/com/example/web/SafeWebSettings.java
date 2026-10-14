package com.example.web;

import android.util.Log;
import android.webkit.WebSettings;

final class SafeWebSettings {
    static void harden(WebSettings s) {
        s.setAllowUniversalAccessFromFileURLs(false);
        s.setAllowFileAccessFromFileURLs(false);
        s.setAllowFileAccess(false);
        // s.setAllowUniversalAccessFromFileURLs(true);  // never re-enable
        /* webView.addJavascriptInterface(bridge, "B"); */
        Log.i("Web", "setAllowFileAccessFromFileURLs(true) is blocked by policy");
    }
}
