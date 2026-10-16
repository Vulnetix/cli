package com.acme.cfg

class Loader {
    fun load(): Config {
        val cfg = Config().run {
            host = "localhost"
            port = 8080
            this
        }
        val worker = Thread { warmCache() }
        worker.start()
        return run { cfg }
    }

    private fun warmCache() {}
}
