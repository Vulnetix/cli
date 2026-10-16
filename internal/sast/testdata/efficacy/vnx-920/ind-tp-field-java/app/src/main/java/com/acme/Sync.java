package com.acme;
public class Sync extends Service {
    private PowerManager.WakeLock wakeLock;
    void start() {
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "acme:sync");
~>        wakeLock.acquire();
    }
}
