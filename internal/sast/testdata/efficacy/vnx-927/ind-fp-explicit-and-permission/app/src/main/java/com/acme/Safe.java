package com.acme;

import android.content.Context;
import android.content.Intent;

class Safe {
    void a(Context c) {
        Intent i = new Intent("com.acme.PING");
        i.setPackage(c.getPackageName());
        c.sendBroadcast(i);
    }
    void b(Context c) {
        Intent i = new Intent("com.acme.SECRET");
        c.sendBroadcast(i, "com.acme.permission.RECEIVE_SECRET");
    }
    void d(Context c) {
        Intent i = new Intent(c, PingReceiver.class);
        c.sendBroadcast(i);
    }
}
