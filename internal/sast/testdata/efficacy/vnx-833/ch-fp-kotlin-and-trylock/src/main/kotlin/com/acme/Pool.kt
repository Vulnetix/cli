package com.acme

class Pool {
    private val a = Any()
    private val b = Any()

    fun one() {
        synchronized(a) {
            synchronized(b) { work() }
        }
    }

    fun two() {
        synchronized(b) {
            synchronized(a) { work() }
        }
    }

    private fun work() {}
}
