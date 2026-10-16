package com.acme

import android.util.Log
import android.webkit.JavascriptInterface

class Safe {
    @JavascriptInterface
    fun log(msg: String) {
        // Runtime.getRuntime().exec(msg) would be bad here
        Log.d("web", "message: startActivity is not called")
    }
}
