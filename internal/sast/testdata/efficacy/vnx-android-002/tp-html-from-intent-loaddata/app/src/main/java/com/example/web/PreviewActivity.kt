package com.example.web

import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class PreviewActivity : AppCompatActivity() {
    private lateinit var preview: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        preview = WebView(this)
        preview.settings.javaScriptEnabled = true
        val html = intent.getStringExtra("html").orEmpty()
~>        preview.loadDataWithBaseURL(
            null,
            html,
            "text/html",
            "utf-8",
            null,
        )
~>        preview.loadData(intent.extras?.getString("body") ?: "", "text/html", "UTF-8")
    }
}
