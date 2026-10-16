package com.acme

// Runtime.getRuntime().exec("su") is not used any more
class Doc {
    val help = "Run Runtime.getRuntime().exec(\"su -c id\") to test"
    fun sh() { Runtime.getRuntime().exec("sh -c id") }
}
