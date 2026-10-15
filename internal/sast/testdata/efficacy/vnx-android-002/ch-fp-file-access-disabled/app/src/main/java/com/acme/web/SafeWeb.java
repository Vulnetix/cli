package com.acme.web;

import android.webkit.WebSettings;
import android.webkit.WebView;

final class SafeWeb {
    static void harden(WebView view) {
        WebSettings s = view.getSettings();
        s.setJavaScriptEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowFileAccessFromFileURLs(false);
        s.setAllowUniversalAccessFromFileURLs(false);
        view.loadUrl("https://www.acme.com/app/");
    }
}
