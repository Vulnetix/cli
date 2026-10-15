package com.acme.sync;

import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;

public class SyncService extends Service {

    private final BroadcastReceiver trigger = new BroadcastReceiver() {
        @Override
~>        public void onReceive(final Context ctx,
                              final Intent received) {
            Bundle args = received.getExtras();
            Uri target = received.getData();
            startSync(target, args);
        }
    };

    @Override
    public void onCreate() {
        registerReceiver(trigger, new IntentFilter("com.acme.sync.START"));
    }

    private void startSync(Uri target, Bundle args) {
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
