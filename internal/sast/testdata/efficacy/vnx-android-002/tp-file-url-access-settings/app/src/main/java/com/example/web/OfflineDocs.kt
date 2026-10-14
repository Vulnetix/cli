package com.example.web

import android.webkit.WebView

fun WebView.enableOfflineDocs() {
    settings.apply {
        javaScriptEnabled = true
~>        allowUniversalAccessFromFileURLs = true
~>        allowFileAccessFromFileURLs = true
    }
    loadUrl("file:///android_asset/docs/index.html")
}
