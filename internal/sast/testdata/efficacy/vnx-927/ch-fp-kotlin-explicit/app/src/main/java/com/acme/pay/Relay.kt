package com.acme.pay

import android.content.ComponentName
import android.content.Context
import android.content.Intent

class Relay(private val context: Context) {
    fun direct(token: String) {
        context.sendBroadcast(Intent(context, TokenReceiver::class.java).putExtra("t", token))
        val viaPackage = Intent("com.acme.pay.TOKEN")
        viaPackage.`package` = context.packageName
        context.sendBroadcast(viaPackage)
        val viaComponent = Intent("com.acme.pay.TOKEN")
        viaComponent.component = ComponentName(context, TokenReceiver::class.java)
        context.sendBroadcast(viaComponent)
        context.sendBroadcast(Intent("com.acme.pay.TOKEN").setPackage(context.packageName))
    }
}
