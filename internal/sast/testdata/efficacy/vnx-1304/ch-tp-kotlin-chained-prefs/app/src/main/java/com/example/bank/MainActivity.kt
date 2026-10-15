package com.example.bank

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.preference.PreferenceManager

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
~>        val loggedIn = PreferenceManager.getDefaultSharedPreferences(this).getBoolean("is_logged_in", false)
        if (loggedIn) showDashboard() else showLogin()
    }
}
