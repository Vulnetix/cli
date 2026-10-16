class Sync {
    fun go(pm: PowerManager) {
        pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "acme:sync").apply {
~>            acquire()
        }
    }
}
