package com.acme.nav

class NavService : Service() {
    private lateinit var lock: PowerManager.WakeLock

    fun begin() {
        lock = (getSystemService(Context.POWER_SERVICE) as PowerManager)
            .newWakeLock(PowerManager.SCREEN_DIM_WAKE_LOCK, "acme:nav")
            .also {
~>                it.acquire()
            }
    }
}
