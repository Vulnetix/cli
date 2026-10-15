package com.acme.promo;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;

public class PromoActivity extends Activity {
    private WebView mWebView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mWebView = new WebView(this);
        WebSettings ws = mWebView.getSettings();
        ws.setJavaScriptEnabled(true);
        String target = getIntent().getStringExtra("link");
~>        mWebView.loadUrl(target);
        setContentView(mWebView);
    }
}
