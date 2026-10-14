package com.example.web;

import android.webkit.WebSettings;
import android.webkit.WebView;

final class ReportViewer {
    static void configure(WebView webView) {
        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
~>        s.setAllowUniversalAccessFromFileURLs(true);
~>        s.setAllowFileAccessFromFileURLs( true );
        webView.loadUrl("file:///android_asset/report/index.html");
    }
}
