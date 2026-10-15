package com.example.sync

import kotlin.concurrent.thread

class Watcher(private val task: () -> Unit) {
    fun watch(): Thread {
        val t = thread(name = "watcher") { task() }
        t.run {
            isDaemon = true
        }
        val action = Runnable { task() }
        action.run()
        return t
    }
}
