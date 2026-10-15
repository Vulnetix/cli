package com.example.web;

import android.webkit.JavascriptInterface;
import java.io.FileOutputStream;
import java.io.IOException;

public class Helper {
    @JavascriptInterface
    public String ping() {
        return "pong";
    }

    // not exposed to JavaScript
    public void export(String path) throws IOException {
        Runtime.getRuntime().exec(new String[]{"sync"});
        new FileOutputStream(path).close();
    }
}
