package com.northwind.onboarding;

import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;

import androidx.appcompat.app.AppCompatActivity;

public class OnboardingWebActivity extends AppCompatActivity {

    private static final String TERMS_URL = "https://www.northwind-payroll.com/legal/terms";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        WebView webView = new WebView(this);
        setContentView(webView);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);

        boolean showTerms = getIntent().getBooleanExtra("show_terms", false);
        if (showTerms) {
            webView.loadUrl(TERMS_URL);
        } else {
            webView.loadUrl("file:///android_asset/onboarding/welcome.html");
        }
    }
}
