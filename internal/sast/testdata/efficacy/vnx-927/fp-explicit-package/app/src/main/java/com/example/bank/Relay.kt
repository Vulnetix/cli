package com.example.bank

import android.content.Context
import android.content.Intent

class Relay(private val context: Context) {
    fun relay(token: String) {
        val intent = Intent("com.example.bank.TOKEN").apply {
            setPackage(context.packageName)
            putExtra("token", token)
        }
        context.sendBroadcast(intent)
    }
}
