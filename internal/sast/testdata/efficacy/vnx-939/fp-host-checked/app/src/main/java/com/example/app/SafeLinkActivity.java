package com.example.app;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebView;

public class SafeLinkActivity extends Activity {
    private static final java.util.Set<String> ALLOWED_HOSTS = java.util.Set.of("help.example.com");

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = new WebView(this);
        Uri uri = getIntent().getData();
        if (uri == null || !"https".equals(uri.getScheme()) || !ALLOWED_HOSTS.contains(uri.getHost())) {
            finish();
            return;
        }
        webView.loadUrl(uri.toString());
    }
}
