package com.example.web;

public class PluginBridge {
    private final android.content.Context ctx;

    public PluginBridge(android.content.Context ctx) {
        this.ctx = ctx;
    }

    @android.webkit.JavascriptInterface
    public void load(String className) {
        try {
~>            Object plugin = Class.forName(className).newInstance();
            ((Runnable) plugin).run();
        } catch (Exception e) {
            // ignored
        }
    }

    @android.webkit.JavascriptInterface
    public void open(String uri) {
        android.content.Intent i = new android.content.Intent(android.content.Intent.ACTION_VIEW);
        i.setData(android.net.Uri.parse(uri));
~>        ctx.startActivity(i);
    }
}
