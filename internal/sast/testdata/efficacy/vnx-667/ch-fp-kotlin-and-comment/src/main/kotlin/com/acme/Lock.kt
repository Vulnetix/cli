package com.acme

class Holder {
    private val name: String = "x"
    fun run() {
        synchronized(name) { println(name) }
    }
}
