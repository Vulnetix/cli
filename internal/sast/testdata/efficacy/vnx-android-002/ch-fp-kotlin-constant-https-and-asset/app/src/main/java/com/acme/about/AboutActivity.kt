package com.acme.about

import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

private const val TERMS_URL = "https://legal.acme.com/terms"

class AboutActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val title = intent.getStringExtra("title")
        supportActionBar?.title = title
        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.loadUrl(TERMS_URL)
        setContentView(web)
    }
}
