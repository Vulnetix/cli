package com.acme.stream;

import android.net.wifi.WifiManager;
import android.os.PowerManager;

public class Player {
    void play(PowerManager pm, WifiManager wm) {
~>        pm.newWakeLock(PowerManager.FULL_WAKE_LOCK, "acme:play").acquire();
        WifiManager.WifiLock lock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "acme");
~>        lock.acquire();
    }
}
