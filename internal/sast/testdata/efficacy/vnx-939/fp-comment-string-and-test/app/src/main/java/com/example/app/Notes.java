package com.example.app;

public class Notes {
    // webView.loadUrl(getIntent().getDataString()) was removed in 2.3
    static final String HINT = "never call webView.loadUrl(getIntent().getDataString())";

    /*
     * Intent.parseUri(intent.getDataString(), 0) is how the old router worked.
     */
    String hint() {
        return HINT;
    }
}
