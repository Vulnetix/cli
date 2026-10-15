package com.example.web;

import android.util.Log;
import android.webkit.JavascriptInterface;
import android.widget.Toast;

public class InfoBridge {
    private final android.content.Context ctx;

    InfoBridge(android.content.Context ctx) { this.ctx = ctx; }

    @JavascriptInterface
    public String getVersion() {
        return "1.4.2";
    }

    @JavascriptInterface
    public void toast(String msg) {
        // Runtime.getRuntime().exec is never used here
        Log.d("InfoBridge", "exec requested: " + msg);
        Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show();
    }
}
