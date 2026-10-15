package com.example.web;

import android.os.Handler;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.widget.Toast;

public class InfoBridge {
    private final android.content.Context ctx;
    private final Handler handler = new Handler();

    InfoBridge(android.content.Context ctx) { this.ctx = ctx; }

    @JavascriptInterface
    public String appVersion() {
        return BuildConfig.VERSION_NAME;
    }

    @JavascriptInterface
    public void toast(final String msg) {
        handler.post(() -> Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show());
        Log.d("InfoBridge", msg);
    }
}
