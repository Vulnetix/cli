package com.acme.reader

import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class ReaderActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val web = WebView(this)
        web.settings.apply {
            javaScriptEnabled = true
~>            allowUniversalAccessFromFileURLs = true
~>            allowFileAccessFromFileURLs = true
        }
        web.loadUrl("file:///android_asset/reader/index.html")
        setContentView(web)
    }
}
