package com.example.web;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebView;

public class LinkActivity extends Activity {
    private static final String TRUSTED = "https://help.example.com/";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = findViewById(R.id.web);
        webView.getSettings().setJavaScriptEnabled(true);
        String url = getIntent().getStringExtra("url");
        if (url != null && url.startsWith(TRUSTED)) {
            webView.loadUrl(url);
        }
    }
}
