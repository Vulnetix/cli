package com.acme.pay

import android.content.Intent
import androidx.appcompat.app.AppCompatActivity

class LoginActivity : AppCompatActivity() {
    private fun onLoggedIn(sessionToken: String) {
        val loggedIn = Intent(ACTION_LOGGED_IN)
        loggedIn.putExtra("token", sessionToken)
~>        sendBroadcast(loggedIn)
~>        sendBroadcast(Intent("com.acme.pay.REFRESH"))
    }

    companion object {
        const val ACTION_LOGGED_IN = "com.acme.pay.LOGGED_IN"
    }
}
