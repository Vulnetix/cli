package com.acme.greet

import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class GreetActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val web = WebView(this)
        web.settings.javaScriptEnabled = true
        web.loadUrl("file:///android_asset/greet.html")
        val name = intent.getStringExtra("name")
~>        web.evaluateJavascript("showGreeting('" + name + "')", null)
~>        web.loadUrl("javascript:setUser('" + intent.getStringExtra("user") + "')")
        setContentView(web)
    }
}
