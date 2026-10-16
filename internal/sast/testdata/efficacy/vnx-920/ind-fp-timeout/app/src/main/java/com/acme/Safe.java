package com.acme;
public class Safe {
    void a(PowerManager pm) {
        PowerManager.WakeLock wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "acme:x");
        wl.acquire(10 * 60 * 1000L);
        wl.release();
    }
}
