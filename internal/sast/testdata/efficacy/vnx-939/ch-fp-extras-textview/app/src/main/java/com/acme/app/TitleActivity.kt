package com.acme.app

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class TitleActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val title = intent.data?.getQueryParameter("title")
        findViewById<TextView>(R.id.title).text = title
        val webView = findViewById<android.webkit.WebView>(R.id.web)
        webView.loadUrl(BuildConfig.HELP_URL)
    }
}
