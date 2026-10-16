package com.acme.sync

class Syncer(private val remote: Remote) {
    fun syncInBackground() {
        val t = Thread({ remote.pull() }, "syncer")
        t.isDaemon = true
~>        t.run()
    }

    fun refresh() {
~>        Thread { remote.push() }.run()
    }
}
