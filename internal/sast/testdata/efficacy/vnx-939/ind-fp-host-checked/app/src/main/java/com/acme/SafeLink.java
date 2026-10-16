package com.acme;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebView;
import java.util.Set;

public class SafeLink extends Activity {
    private static final Set<String> ALLOWED_HOSTS = Set.of("www.acme.com");

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        WebView webView = findViewById(R.id.web);
        Uri uri = getIntent().getData();
        if (uri == null || !"https".equals(uri.getScheme()) || !ALLOWED_HOSTS.contains(uri.getHost())) {
            finish();
            return;
        }
        webView.loadUrl(uri.toString());
    }
}
