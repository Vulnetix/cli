package com.example.bank;

import android.content.Context;
import android.content.Intent;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

class LocalEvents {
    void publish(Context ctx, String account) {
        Intent status = new Intent("com.example.bank.STATUS");
        status.putExtra("account", account);
        LocalBroadcastManager.getInstance(ctx).sendBroadcast(status);

        LocalBroadcastManager manager = LocalBroadcastManager.getInstance(ctx);
        Intent again = new Intent("com.example.bank.STATUS");
        manager.sendBroadcast(again);
    }
}
