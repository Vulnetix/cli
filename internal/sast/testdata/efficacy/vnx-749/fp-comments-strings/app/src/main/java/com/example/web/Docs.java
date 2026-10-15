package com.example.web;

import android.webkit.JavascriptInterface;

public class Docs {
    @JavascriptInterface
    public String help() {
        // Runtime.getRuntime().exec(cmd) is never exposed here
        return "do not call Runtime.getRuntime().exec( from a bridge";
    }
}
