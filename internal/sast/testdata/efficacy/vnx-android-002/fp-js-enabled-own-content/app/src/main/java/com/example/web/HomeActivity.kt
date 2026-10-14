package com.example.web

import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class HomeActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.addJavascriptInterface(AppBridge(this), "App")
        web.loadUrl("https://app.example.com/home")
        web.loadUrl("file:///android_asset/onboarding.html")
        web.loadUrl(BuildConfig.HELP_CENTER_URL)
        setContentView(web)
    }
}
