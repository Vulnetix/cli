package com.example.sync

class Mirror(private val job: Runnable) {
    private lateinit var worker: Thread

    fun kick() {
~>        Thread(job, "mirror").run()
    }

    fun again() {
        worker = Thread(job)
~>        worker.run()
    }
}
