package com.acme.app

import android.content.Context
import android.content.Intent

class Notifier(private val mContext: Context) {
    fun loggedIn(token: String) {
        val intent = Intent("com.acme.app.LOGGED_IN")
        intent.putExtra("token", token)
        intent.setPackage(mContext.packageName)
        mContext.sendBroadcast(intent)
    }

    fun ping() {
        val ping = Intent("com.acme.app.PING")
        mContext.sendBroadcast(ping)
    }
}
