package com.example.tools

class Root {
    fun run(cmd: String): Process =
~>        Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))

    fun builder(cmd: String): Process {
~>        return ProcessBuilder(listOf("su", "-c", cmd)).start()
    }

    fun twoLine(cmd: String) {
        val argv = arrayOf("su", "-c", cmd)
~>        Runtime.getRuntime().exec(argv)
    }
}
