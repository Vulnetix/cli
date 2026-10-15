package com.acme

import android.util.Log

class LoginActivity {
    fun onLogin(username: String, password: String) {
~>        Log.d(TAG, "login $username / $password")
    }
}
