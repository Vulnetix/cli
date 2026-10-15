package com.example.tools

// Runtime.getRuntime().exec("su") must never be called by this app.
class Notes {
    val help = "Do not call exec(\"su\") from the app"
    fun log() = println("Runtime.getRuntime().exec(\"su\") is disallowed")
}
