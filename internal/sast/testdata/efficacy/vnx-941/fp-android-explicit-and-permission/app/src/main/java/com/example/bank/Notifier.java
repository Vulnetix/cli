package com.example.bank;

import android.content.Context;
import android.content.Intent;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

public class Notifier {
    private final Context context;

    Notifier(Context context) { this.context = context; }

    void explicitReceiver(String token) {
        Intent i = new Intent(context, TokenReceiver.class);
        i.putExtra("token", token);
        context.sendBroadcast(i);
    }

    void scoped(String token) {
        Intent i = new Intent("com.example.bank.TOKEN");
        i.setPackage("com.example.bank");
        i.putExtra("token", token);
        context.sendBroadcast(i);
    }

    void withPermission(String token) {
        Intent i = new Intent("com.example.bank.TOKEN");
        i.putExtra("token", token);
        context.sendBroadcast(i, "com.example.bank.permission.RECEIVE_TOKEN");
    }

    void local(String token) {
        Intent i = new Intent("com.example.bank.TOKEN");
        i.putExtra("token", token);
        LocalBroadcastManager.getInstance(context).sendBroadcast(i);
    }

    void noExtras() {
        Intent refresh = new Intent("com.example.bank.REFRESH");
        context.sendBroadcast(refresh);
    }
}
