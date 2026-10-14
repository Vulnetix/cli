package com.example.web;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

public class ReceiptActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = findViewById(R.id.receipt);
        webView.getSettings().setJavaScriptEnabled(false);
        webView.loadUrl(getIntent().getStringExtra("receipt_url"));
    }
}
