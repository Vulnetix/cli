package com.example

class Config {
    // Never call thread.run() directly; use start()
    val hint = "new Thread(task).run() runs on the caller"

    fun build(): Map<String, String> {
        val t = Thread { println("x") }
        t.start()
        return mutableMapOf<String, String>().run {
            put("a", "b")
            this
        }
    }
}
