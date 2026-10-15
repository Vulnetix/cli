package com.acme.app;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebView;

public class DeepLinkActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView web = new WebView(this);
        setContentView(web);
        Uri link = getIntent().getData();
        String url = link == null ? null : link.getQueryParameter("url");
        if (url == null || url.isEmpty()) {
            finish();
            return;
        }
~>        web.loadUrl(url);
    }
}
