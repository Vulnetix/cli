package com.example.web

import android.content.Intent
import androidx.browser.customtabs.CustomTabsIntent

class ArticleImages(private val loader: ImageLoader) {
    fun show(intent: Intent, tabs: CustomTabsIntent, ctx: android.content.Context) {
        loader.loadUrl(intent.getStringExtra("image"))
        tabs.launchUrl(ctx, android.net.Uri.parse(intent.getStringExtra("link")))
    }
}
