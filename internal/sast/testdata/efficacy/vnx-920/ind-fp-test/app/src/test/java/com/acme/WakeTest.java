package com.acme;
public class WakeTest {
    void t(PowerManager pm) {
        pm.newWakeLock(PowerManager.FULL_WAKE_LOCK, "t").acquire();
    }
}
