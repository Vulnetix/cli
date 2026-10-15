package com.example.bank

import android.content.Context
import android.content.Intent

class TokenRelay(private val context: Context) {
    fun relay(token: String) {
        val intent = Intent("com.example.bank.TOKEN").apply {
            putExtra("token", token)
        }
~>        context.sendBroadcast(intent)
    }

    fun relayTyped(token: String) {
        val out: Intent = Intent()
        out.action = "com.example.bank.TOKEN"
        out.putExtra("token", token)
~>        context.sendBroadcast(out)
    }
}
