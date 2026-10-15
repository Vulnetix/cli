package com.acme.sync;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import androidx.annotation.NonNull;

public final class RestartSyncReceiver extends BroadcastReceiver {

    @Override
~>    public void onReceive(@NonNull Context context, @NonNull Intent intent) {
        String account = intent.getStringExtra("account");
        SyncScheduler.forceFullSync(context, account);
    }
}
