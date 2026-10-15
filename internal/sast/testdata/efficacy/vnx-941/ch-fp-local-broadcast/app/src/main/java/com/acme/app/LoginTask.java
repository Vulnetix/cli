package com.acme.app;

import android.content.Context;
import android.content.Intent;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

public class LoginTask {
    void onLoggedIn(Context context, String sessionToken) {
        Intent intent = new Intent("com.acme.app.ACTION_LOGIN");
        intent.putExtra("session", sessionToken);
        LocalBroadcastManager.getInstance(context).sendBroadcast(intent);

        Intent sync = new Intent("com.acme.app.SYNC");
        sync.putExtra("account", "a");
        context.sendBroadcast(sync, "com.acme.app.permission.INTERNAL");
    }
}
