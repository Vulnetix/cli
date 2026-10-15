package com.acme.upload

import android.content.Context
import android.os.PowerManager

class Uploader(private val ctx: Context) {
    private val wl: PowerManager.WakeLock =
        (ctx.getSystemService(Context.POWER_SERVICE) as PowerManager)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "acme:upload")

    fun run() {
~>        wl.acquire()
        upload()
        wl.release()
    }
}
