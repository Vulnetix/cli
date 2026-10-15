package com.acme.app;

import android.content.Context;
import android.content.Intent;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

public class Bus {
    private final LocalBroadcastManager broadcaster;

    Bus(Context context) {
        broadcaster = LocalBroadcastManager.getInstance(context);
    }

    void publish(String token) {
        Intent intent = new Intent("com.acme.app.TOKEN");
        intent.putExtra("token", token);
        broadcaster.sendBroadcast(intent);
    }
}
