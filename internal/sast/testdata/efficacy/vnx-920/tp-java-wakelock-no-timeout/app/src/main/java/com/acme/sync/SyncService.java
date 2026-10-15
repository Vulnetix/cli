package com.acme.sync;

import android.content.Context;
import android.os.PowerManager;

public class SyncService {
    private PowerManager.WakeLock wakeLock;

    void start(Context ctx) {
        PowerManager pm = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "acme:sync");
~>        wakeLock.acquire();
        doSync();
        wakeLock.release();
    }
}
