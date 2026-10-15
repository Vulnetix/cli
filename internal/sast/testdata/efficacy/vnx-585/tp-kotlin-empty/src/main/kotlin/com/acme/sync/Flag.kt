package com.acme.sync

class Flag {
    private val lock = Any()

    fun touch() {
~>        synchronized(lock) {}
    }
}
