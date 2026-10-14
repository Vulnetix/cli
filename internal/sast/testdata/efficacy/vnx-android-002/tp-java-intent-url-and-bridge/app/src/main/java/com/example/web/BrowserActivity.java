package com.example.web;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

public class BrowserActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = findViewById(R.id.web);
        webView.getSettings().setJavaScriptEnabled(true);
~>        webView.addJavascriptInterface(new WalletBridge(this), "Wallet");
        String target = getIntent().getStringExtra("url");
~>        webView.loadUrl(target);
    }
}
