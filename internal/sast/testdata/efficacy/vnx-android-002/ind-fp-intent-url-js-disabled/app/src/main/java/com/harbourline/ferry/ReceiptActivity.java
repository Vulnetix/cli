package com.harbourline.ferry;

import android.os.Bundle;
import android.webkit.WebView;

import androidx.appcompat.app.AppCompatActivity;

public class ReceiptActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = new WebView(this);
        setContentView(webView);

        // Receipts are static HTML; scripting stays off.
        webView.getSettings().setJavaScriptEnabled(false);

        String receiptUrl = getIntent().getStringExtra("receipt_url");
        webView.loadUrl(receiptUrl);
    }
}
