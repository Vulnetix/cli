package com.acme.otp

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony

class OtpReceiver : BroadcastReceiver() {
~>    override fun onReceive(context: Context, intent: Intent) {
        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        OtpStore.accept(messages.first().messageBody)
    }
}

fun register(context: Context) {
    context.registerReceiver(OtpReceiver(), android.content.IntentFilter("android.provider.Telephony.SMS_RECEIVED"))
}
