package com.example.web;

import android.webkit.JavascriptInterface;
import java.io.File;

public class Maintenance {
    @JavascriptInterface
    public int cacheSize() {
        return new File("/data/local/tmp").list().length;
    }

    void clearCache() throws Exception {
        Runtime.getRuntime().exec(new String[] {"rm", "-rf", "/data/local/tmp/cache"});
        new File("/data/local/tmp/cache.db").delete();
    }
}
