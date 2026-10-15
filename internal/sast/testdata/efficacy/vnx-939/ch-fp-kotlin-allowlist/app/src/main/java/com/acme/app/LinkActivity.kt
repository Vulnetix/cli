package com.acme.app

import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class LinkActivity : AppCompatActivity() {
    private val allowedHosts = setOf("help.acme.com", "www.acme.com")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        setContentView(webView)
        val uri = intent.data ?: return
        if (uri.scheme != "https" || uri.host !in allowedHosts) {
            finish()
            return
        }
        webView.loadUrl(uri.toString())
    }
}
