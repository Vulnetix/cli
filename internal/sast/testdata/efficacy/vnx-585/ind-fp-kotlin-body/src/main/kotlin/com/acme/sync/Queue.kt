package com.acme.sync

class Queue<T> {
    private val lock = Any()
    private val items = ArrayDeque<T>()

    fun push(item: T) {
        synchronized(lock) {
            items.addLast(item)
        }
    }

    fun pop(): T? = synchronized(lock) { items.removeFirstOrNull() }

    @Synchronized
    fun clear() {}
}
