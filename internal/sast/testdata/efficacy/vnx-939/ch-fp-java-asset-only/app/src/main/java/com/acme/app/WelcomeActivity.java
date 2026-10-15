package com.acme.app;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebView;

public class WelcomeActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = new WebView(this);
        setContentView(webView);
        Uri data = getIntent().getData();
        Log.d("Welcome", "opened from " + data);
        webView.loadUrl("file:///android_asset/welcome.html");
    }
}
