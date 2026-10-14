package com.example.web

import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class HelpActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        val page: String = intent.data?.getQueryParameter("page") ?: return
~>        web.loadUrl(page)
~>        web.loadUrl(intent.getStringExtra(EXTRA_URL)!!)
        setContentView(web)
    }

    companion object {
        const val EXTRA_URL = "extra_url"
    }
}
