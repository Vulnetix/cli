package com.acme.wipe

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class WipeReceiver : BroadcastReceiver() {

~>    override fun onReceive(context: Context?, intent: Intent?) {
        val account = intent?.extras?.getString("account")
        val path = intent!!.data?.path
        Storage.wipe(context, account, path)
    }
}
