package com.example.web;

import android.app.Activity;
import android.os.Bundle;
import android.os.Environment;
import android.webkit.WebView;

public class StatementActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String user = getIntent().getStringExtra("user");
        WebView mWebView = (WebView) findViewById(R.id.statement);
        mWebView.getSettings().setJavaScriptEnabled(true);
~>        mWebView.loadUrl("file://" + Environment.getExternalStorageDirectory() + "/statement_" + user + ".html");
    }

    void showOffers(WebView view) {
~>        view.loadUrl("http://promo.example.com/offers.html");
    }
}
