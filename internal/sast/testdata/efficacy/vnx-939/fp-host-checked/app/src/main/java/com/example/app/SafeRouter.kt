package com.example.app

import android.app.Activity
import android.os.Bundle
import android.webkit.WebView

class SafeRouter : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val web = WebView(this)
        val link = intent.data ?: return
        if (link.host != "docs.example.com") return
        web.loadUrl(link.toString())
    }
}
