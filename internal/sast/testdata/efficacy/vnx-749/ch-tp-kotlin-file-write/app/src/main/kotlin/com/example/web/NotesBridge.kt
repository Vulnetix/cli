package com.example.web

import android.content.Context
import android.webkit.JavascriptInterface
import java.io.File

class NotesBridge(private val context: Context) {
    @JavascriptInterface
    fun save(name: String, body: String) {
~>        File(context.filesDir, name).writeText(body)
    }

    @JavascriptInterface
    fun remove(name: String): Boolean {
~>        return File(context.filesDir, name).delete()
    }
}
