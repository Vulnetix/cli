package com.acme.mail;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;

public class MessageView extends Activity {
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        WebView body = findViewById(R.id.body);
        body.getSettings().setJavaScriptEnabled(true);
        String html = getIntent().getStringExtra("html_body");
~>        body.loadDataWithBaseURL(null, html,
                "text/html", "utf-8", null);
    }
}
