package com.example.web;

import android.webkit.JavascriptInterface;

public class BridgeTest {
    static class Fake {
        @JavascriptInterface
        public void run(String c) throws Exception {
            Runtime.getRuntime().exec(c);
        }
    }
}
