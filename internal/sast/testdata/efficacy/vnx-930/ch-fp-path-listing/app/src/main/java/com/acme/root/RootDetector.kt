package com.acme.root

import java.io.File

class RootDetector {
    private val suPaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su")

    fun isRooted(): Boolean {
        if (suPaths.any { File(it).exists() }) return true
        val p = Runtime.getRuntime().exec(arrayOf("ls", "-l", "/system/xbin/su"))
        val q = ProcessBuilder("which", "su").start()
        return p.waitFor() == 0 || q.waitFor() == 0
    }
}
