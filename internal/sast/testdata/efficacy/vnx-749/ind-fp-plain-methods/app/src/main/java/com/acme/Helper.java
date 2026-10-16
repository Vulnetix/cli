package com.acme;

import android.content.Context;
import android.webkit.JavascriptInterface;
import android.widget.Toast;

public class Helper {
    private final Context ctx;
    Helper(Context ctx) { this.ctx = ctx; }

    @JavascriptInterface
    public String version() {
        return "1.4.2";
    }

    @JavascriptInterface
    public void toast(String msg) {
        Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show();
    }

    // not exposed to the webview, no annotation
    public void launch(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
        ctx.startActivity(new android.content.Intent());
    }
}
