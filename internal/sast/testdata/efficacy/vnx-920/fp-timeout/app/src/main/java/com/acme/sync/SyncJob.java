package com.acme.sync;

import android.os.PowerManager;

public class SyncJob {
    void run(PowerManager pm) {
        PowerManager.WakeLock wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "acme:job");
        wakeLock.acquire(10 * 60 * 1000L);
        try {
            work();
        } finally {
            wakeLock.release();
        }
    }
}
