package com.acme;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;

class Comp {
    void f(Context c) {
        Intent i = new Intent("com.acme.X");
        i.setComponent(new ComponentName(c, XReceiver.class));
        c.sendBroadcast(i);
    }
}
