package com.acme

class Gate(private val lock: Any) {
    fun pass() {
~>        synchronized(lock) { }
    }
}
