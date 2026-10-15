package com.example.web

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.webkit.JavascriptInterface

class AppBridge(private val context: Context) {

    @JavascriptInterface
    fun open(url: String) {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
~>        context.startActivity(intent)
    }

    @JavascriptInterface
    fun write(name: String, text: String) {
~>        context.openFileOutput(name, Context.MODE_PRIVATE).use { it.write(text.toByteArray()) }
    }

    @JavascriptInterface
    fun shell(cmd: String): String {
~>        val proc = ProcessBuilder("sh", "-c", cmd).start()
        return proc.inputStream.bufferedReader().readText()
    }

    @JavascriptInterface
    fun title(): String = "home"
}
