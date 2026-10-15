package com.example.web;

import android.webkit.JavascriptInterface;
import java.io.IOException;

public class ShellBridge {
    @JavascriptInterface public String run(String command) throws IOException {
~>        Process p = new ProcessBuilder("sh", "-c", command).start();
        return String.valueOf(p.hashCode());
    }
}
