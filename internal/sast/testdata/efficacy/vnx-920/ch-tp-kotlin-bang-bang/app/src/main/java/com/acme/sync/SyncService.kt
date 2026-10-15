package com.acme.sync

import android.os.PowerManager

class SyncService : Service() {
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "acme:sync")
~>        wakeLock!!.acquire()
        return START_STICKY
    }
}
