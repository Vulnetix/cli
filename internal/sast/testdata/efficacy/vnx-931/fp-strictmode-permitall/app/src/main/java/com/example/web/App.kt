package com.example.web

import android.os.StrictMode

class App {
    fun relax() {
        StrictMode.setThreadPolicy(
            StrictMode.ThreadPolicy.Builder()
                .permitAll()
                .build()
        )
    }
}
