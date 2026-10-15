package com.acme.io

class Uploader(private val pm: PowerManager) {
    private val permits = Semaphore(4)
    private val wakeLock: PowerManager.WakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "acme:up")

    suspend fun upload(f: File) {
        permits.acquire()
        wakeLock.acquire(10 * 60 * 1000L)
        try {
            send(f)
        } finally {
            wakeLock.release()
            permits.release()
        }
    }
}
