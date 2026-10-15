package com.acme.root

class Remounter {
    fun remount(): Int {
        val pb = ProcessBuilder()
~>        pb.command("su", "-c", "mount -o rw,remount /system")
        return pb.start().waitFor()
    }

    fun systemless(cmd: String): Process =
~>        Runtime.getRuntime().exec(arrayOf("/su/bin/su", "-c", cmd))
}
