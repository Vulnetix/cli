package com.acme.notify;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class FakeReceiver extends BroadcastReceiver {
    String last;

    @Override
    public void onReceive(Context context, Intent intent) {
        last = intent.getStringExtra("payload");
    }
}
