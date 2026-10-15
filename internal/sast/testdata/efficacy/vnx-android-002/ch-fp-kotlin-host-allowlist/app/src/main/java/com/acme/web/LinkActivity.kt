package com.acme.web

import android.net.Uri
import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class LinkActivity : AppCompatActivity() {
    private val allowedHosts = setOf("www.acme.com", "help.acme.com")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        val link = intent.data ?: return
        if (link.scheme != "https" || link.host !in allowedHosts) {
            finish()
            return
        }
        web.loadUrl(link.toString())
        setContentView(web)
    }
}
