package com.acme;
public class Player {
    void play(PowerManager pm) {
~>        pm.newWakeLock(PowerManager.FULL_WAKE_LOCK, "acme:play").acquire();
    }
}
