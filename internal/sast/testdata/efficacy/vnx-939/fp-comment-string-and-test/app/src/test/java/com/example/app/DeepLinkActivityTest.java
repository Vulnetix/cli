package com.example.app;

public class DeepLinkActivityTest {
    public void loadsLink() {
        webView.loadUrl(getIntent().getDataString());
    }
}
