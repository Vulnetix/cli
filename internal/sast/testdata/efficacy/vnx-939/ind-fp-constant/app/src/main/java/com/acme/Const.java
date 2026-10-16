package com.acme;

import android.app.Activity;
import android.content.Intent;

public class Const extends Activity {
    void go() {
        webView.loadUrl("https://www.acme.com/help");
        Intent i = new Intent();
        i.setClassName(this, "com.acme.SettingsActivity");
        // webView.loadUrl(getIntent().getDataString());
        String s = "webView.loadUrl(getIntent().getDataString())";
    }
}
