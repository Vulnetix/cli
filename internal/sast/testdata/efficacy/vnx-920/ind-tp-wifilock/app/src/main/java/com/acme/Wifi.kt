class Wifi(wm: WifiManager) {
    private val lock: WifiManager.WifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL, "acme")
    fun hold() {
~>        lock.acquire()
    }
}
