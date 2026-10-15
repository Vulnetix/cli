package com.example.app

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.os.Bundle

class RouterActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val next = intent?.data?.getQueryParameter("next")
~>        val launch = Intent.parseUri(next, Intent.URI_INTENT_SCHEME)
        startActivity(launch)
        finish()
    }

    fun openScreen() {
        val screen = intent.data?.lastPathSegment
        val target = Intent()
~>        target.component = ComponentName(packageName, screen!!)
        startActivity(target)
    }
}
