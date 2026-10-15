package com.acme

import android.os.PowerManager

class Beacon(pm: PowerManager) {
    // wakeLock.acquire() without a timeout drains the battery
    private val wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "acme:beacon")

    fun ping() {
        wakeLock.acquire(30_000L)
        val doc = "call wakeLock.acquire() only with a timeout"
    }
}
