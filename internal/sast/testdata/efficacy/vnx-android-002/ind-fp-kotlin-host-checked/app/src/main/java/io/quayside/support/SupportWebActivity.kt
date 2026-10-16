package io.quayside.support

import android.net.Uri
import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

class SupportWebActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        setContentView(webView)
        webView.settings.javaScriptEnabled = true

        val requested = intent.getStringExtra(EXTRA_URL) ?: DEFAULT_URL
        val uri = Uri.parse(requested)
        if (uri.scheme != "https" || uri.host != "help.quayside.io") {
            finish()
            return
        }
        webView.loadUrl(requested)
    }

    companion object {
        const val EXTRA_URL = "support_url"
        private const val DEFAULT_URL = "https://help.quayside.io/"
    }
}
