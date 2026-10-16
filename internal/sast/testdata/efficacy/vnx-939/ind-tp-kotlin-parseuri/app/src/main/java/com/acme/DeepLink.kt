package com.acme

import android.content.Intent
import androidx.appcompat.app.AppCompatActivity

class DeepLink : AppCompatActivity() {
    fun handle() {
        val next = intent?.data?.getQueryParameter("next")
~>        val launch = Intent.parseUri(next, Intent.URI_INTENT_SCHEME)
        startActivity(launch)
    }
}
