package com.acme;

import android.webkit.JavascriptInterface;

public class BridgeTest {
    @JavascriptInterface
    public void danger(String c) throws Exception {
        Runtime.getRuntime().exec(c);
    }
}
