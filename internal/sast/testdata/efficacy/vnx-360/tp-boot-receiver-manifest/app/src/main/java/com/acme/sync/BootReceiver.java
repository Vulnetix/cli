package com.acme.sync;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class BootReceiver extends BroadcastReceiver {
    @Override
~>    public void onReceive(Context context, Intent intent) {
        String account = intent.getStringExtra("account");
        SyncService.wipeAndResync(context, account);
    }
}
