package com.northwind.help;

import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import androidx.appcompat.app.AppCompatActivity;

public class HelpBrowserActivity extends AppCompatActivity {

    public static final String EXTRA_ARTICLE_URL = "com.northwind.help.ARTICLE_URL";

    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_help_browser);

        webView = findViewById(R.id.help_web_view);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        webView.setWebViewClient(new WebViewClient());

        String articleUrl = getIntent().getStringExtra(EXTRA_ARTICLE_URL);
        if (articleUrl != null) {
~>            webView.loadUrl(articleUrl);
        }
    }
}
