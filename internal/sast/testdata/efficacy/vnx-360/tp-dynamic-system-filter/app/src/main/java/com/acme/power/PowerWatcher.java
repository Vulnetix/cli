package com.acme.power;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;

public class PowerWatcher {
    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override
~>        public void onReceive(final Context ctx, final Intent intent) {
            Uploader.flushPendingLogs(ctx);
        }
    };

    void start(Context context) {
        IntentFilter filter = new IntentFilter(Intent.ACTION_POWER_CONNECTED);
        context.registerReceiver(receiver, filter);
    }
}
