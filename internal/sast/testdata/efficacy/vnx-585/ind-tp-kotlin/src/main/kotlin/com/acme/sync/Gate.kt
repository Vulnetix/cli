package com.acme.sync

class Gate {
    private val lock = Any()
    private var open = false

    fun pass() {
~>        synchronized(lock) {}
    }

    fun drain() {
~>        synchronized(lock) {
            // nothing here yet
        }
        open = false
    }
}
