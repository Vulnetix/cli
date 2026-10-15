package com.example.bank;

import android.content.Context;
import android.content.Intent;

class Explicit {
    void publish(Context ctx) {
        Intent direct = new Intent(ctx, RefreshReceiver.class);
        direct.putExtra("force", true);
        ctx.sendBroadcast(direct);
        sendBroadcast(new Intent(ctx, RefreshReceiver.class));
    }

    void sendBroadcast(Intent i) { }
}
