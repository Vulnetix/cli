package com.acme.greet

import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class ThemeActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        val dark = intent.getBooleanExtra("dark", false)
        web.loadUrl("file:///android_asset/theme.html")
        web.evaluateJavascript("applyTheme(" + JSONObject.quote(if (dark) "dark" else "light") + ")", null)
        setContentView(web)
    }
}
