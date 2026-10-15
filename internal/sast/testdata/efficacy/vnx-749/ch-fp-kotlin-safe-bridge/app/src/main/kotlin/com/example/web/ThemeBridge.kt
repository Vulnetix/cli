package com.example.web

import android.webkit.JavascriptInterface

class ThemeBridge(private val prefs: Map<String, String>) {
    @JavascriptInterface
    fun theme(): String = prefs["theme"] ?: "light"

    @JavascriptInterface
    fun log(message: String) {
        println("bridge: $message")
    }

    fun purge(dir: java.io.File) {
        dir.deleteRecursively()
    }
}
