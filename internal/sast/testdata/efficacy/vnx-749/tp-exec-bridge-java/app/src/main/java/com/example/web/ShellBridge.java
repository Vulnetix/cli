package com.example.web;

import android.webkit.JavascriptInterface;
import java.io.IOException;

public class ShellBridge {
    @JavascriptInterface
    public String run(String cmd) throws IOException {
~>        Process p = Runtime.getRuntime().exec(cmd);
        return String.valueOf(p.hashCode());
    }

    @android.webkit.JavascriptInterface
    public void runArgs(String a, String b) throws IOException {
~>        new ProcessBuilder(a, b)
            .start();
    }

    @JavascriptInterface public String version() { return "1.0"; }
}
