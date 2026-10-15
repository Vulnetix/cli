package com.acme.app

import android.content.Context
import android.content.Intent
import androidx.fragment.app.Fragment

class Notifier(private val mContext: Context) {
    fun loggedIn(token: String) {
        val intent = Intent("com.acme.app.LOGGED_IN")
        intent.putExtra("token", token)
~>        mContext.sendBroadcast(intent)
    }
}

class ProfileFragment : Fragment() {
    fun saved(email: String) {
        val update = Intent("com.acme.app.PROFILE_SAVED").apply {
            putExtra("email", email)
        }
~>        context?.sendBroadcast(update)
    }
}
