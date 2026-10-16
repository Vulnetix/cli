package com.acme.notes.sync;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import org.junit.Test;

public class FakeBootReceiverTest {
    @Test
    public void receives() {
        BroadcastReceiver r = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                SyncScheduler.resetAndSchedule(context, intent.getStringExtra("account"));
            }
        };
        IntentFilter filter = new IntentFilter(Intent.ACTION_BOOT_COMPLETED);
        context().registerReceiver(r, filter);
    }

    private Context context() { return null; }
}
