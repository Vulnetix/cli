package com.acme.wallet

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony

class SmsCodeReceiver : BroadcastReceiver() {
~>    override fun onReceive(context: Context, intent: Intent) {
        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        val body = messages.joinToString("") { it.messageBody }
        CodeVerifier.submit(context, body)
    }
}
