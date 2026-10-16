package com.acme

class Rooter {
    fun run(cmd: String) {
~>        Runtime.getRuntime().exec(arrayOf("/system/xbin/su", "-c", cmd))
    }
}
