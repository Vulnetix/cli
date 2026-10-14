package com.example.web

import android.net.Uri
import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class DeepLinkActivity : AppCompatActivity() {
    private val allowedHosts = setOf("help.example.com", "docs.example.com")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        val link = intent.data ?: return
        if (link.scheme == "https" && link.host in allowedHosts) {
            web.loadUrl(link.toString())
        }
    }
}
