package com.acme.app

import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class OpenActivity : AppCompatActivity() {
    private lateinit var webView: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        webView = WebView(this)
        setContentView(webView)
        intent?.data?.let { uri ->
            if (uri.scheme == "https" && uri.host == "help.acme.com") {
                webView.loadUrl(uri.toString())
            }
        }
    }
}
