package com.acme.sync

class Queue {
    private val lock = Any()
    private val items = mutableListOf<String>()

    fun add(s: String) {
        synchronized(lock) { items.add(s) }
        synchronized(lock) {
            items.clear()
        }
    }
}
