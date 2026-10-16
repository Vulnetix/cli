package com.northwind.reports;

import android.content.Context;
import android.webkit.WebSettings;
import android.webkit.WebView;

public final class OfflineReportViewer {

    private final WebView webView;

    public OfflineReportViewer(Context context) {
        this.webView = new WebView(context);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccess(true);
~>        settings.setAllowUniversalAccessFromFileURLs(true);
~>        settings.setAllowFileAccessFromFileURLs(true);
    }

    public void show(String reportName) {
        webView.loadUrl("file:///android_asset/reports/" + reportName + ".html");
    }
}
