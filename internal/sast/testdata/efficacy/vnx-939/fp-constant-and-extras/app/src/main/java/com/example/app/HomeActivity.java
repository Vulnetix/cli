package com.example.app;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

public class HomeActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = new WebView(this);
        webView.loadUrl("https://www.example.com/home");
        String title = getIntent().getStringExtra("title");
        setTitle(title);
        Intent next = new Intent();
        next.setClassName(this, "com.example.app.SettingsActivity");
        startActivity(next);
        Class<?> c = Class.forName("com.example.app.Plugin");
    }
}
