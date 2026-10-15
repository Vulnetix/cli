package com.acme.ui;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class RefreshReceiver extends BroadcastReceiver {

    private final Runnable refresh;

    public RefreshReceiver(Runnable refresh) {
        this.refresh = refresh;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        refresh.run();
    }

    public Intent describe(Intent intent) {
        return intent.putExtra("source", intent.getStringExtra("origin"));
    }
}
