package com.acme;

public class WakeTest {
    @Test
    public void holds() {
        PowerManager.WakeLock wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "t");
        wl.acquire();
        assertTrue(wl.isHeld());
    }
}
