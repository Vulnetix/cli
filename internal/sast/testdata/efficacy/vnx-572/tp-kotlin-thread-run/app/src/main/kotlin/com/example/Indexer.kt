package com.example

class Indexer(private val work: Runnable) {
    fun go() {
        val t = Thread(work, "indexer")
~>        t.run()
~>        Thread { rebuild() }.run()
    }

    private fun rebuild() {}
}
