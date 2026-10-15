package com.acme

class Cache {
    private val lock = Any()
    private var value = 0

    @Synchronized
    fun clear() {}

    fun bump() = synchronized(lock) { value++ }

    fun read(): Int {
        synchronized(lock) {
            return value
        }
    }
}
