package com.acme;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

public class LinkActivity extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        WebView webView = findViewById(R.id.web);
~>        webView.loadUrl(getIntent().getDataString());
    }
}
