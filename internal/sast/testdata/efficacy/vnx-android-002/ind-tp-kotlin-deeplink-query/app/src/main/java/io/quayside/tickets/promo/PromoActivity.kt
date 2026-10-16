package io.quayside.tickets.promo

import android.annotation.SuppressLint
import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class PromoActivity : AppCompatActivity() {

    private lateinit var webView: WebView

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        webView = WebView(this)
        setContentView(webView)

        webView.settings.apply {
            javaScriptEnabled = true
            loadWithOverviewMode = true
        }

        val campaign = intent.data?.getQueryParameter("landing")
            ?: return finish()
~>        webView.loadUrl(campaign)
    }
}
