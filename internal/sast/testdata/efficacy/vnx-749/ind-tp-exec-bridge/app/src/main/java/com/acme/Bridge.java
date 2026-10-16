package com.acme;

import android.webkit.JavascriptInterface;
import java.io.IOException;

public class Bridge {
    @JavascriptInterface
    public String run(String cmd) throws IOException {
~>        Process p = Runtime.getRuntime().exec(cmd);
        return p.toString();
    }
}
