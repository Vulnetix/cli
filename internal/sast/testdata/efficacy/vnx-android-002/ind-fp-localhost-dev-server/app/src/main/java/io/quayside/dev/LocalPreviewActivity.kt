package io.quayside.dev

import android.os.Bundle
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity

/**
 * Embedded preview of the bundled web app served by the on-device asset server.
 * Note: never call webView.loadUrl(intent.getStringExtra("url")) here.
 */
class LocalPreviewActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        setContentView(webView)
        webView.settings.javaScriptEnabled = true
        webView.loadUrl("http://localhost:8080/index.html")
    }
}
