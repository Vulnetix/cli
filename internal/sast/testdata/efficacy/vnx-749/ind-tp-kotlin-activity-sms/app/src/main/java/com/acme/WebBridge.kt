package com.acme

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.telephony.SmsManager
import android.webkit.JavascriptInterface

class WebBridge(private val context: Context) {
    @JavascriptInterface
    fun open(url: String) {
~>        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
    }

    @JavascriptInterface
    fun text(number: String, body: String) {
~>        SmsManager.getDefault().sendTextMessage(number, null, body, null, null)
    }
}
