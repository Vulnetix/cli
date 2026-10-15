package com.acme.power;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;

public class PowerMonitor {
    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override
~>        public void onReceive(Context context, Intent intent) {
            int level = intent.getIntExtra("level", -1);
            Uploader.flush(context, level);
        }
    };

    public void start(Context context) {
        IntentFilter filter = new IntentFilter();
        filter.addAction(Intent.ACTION_BATTERY_LOW);
        context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED);
    }
}
