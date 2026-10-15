package com.acme.player;

import android.os.PowerManager;

public class PlaybackService extends Service {
    private PowerManager.WakeLock mWakeLock;

    @Override
    public void onCreate() {
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        mWakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,
                "acme:playback");
    }

    void startPlayback() {
~>        this.mWakeLock.acquire();
        player.start();
    }
}
