package com.example.bank;

import android.content.Context;
import android.content.Intent;

class StatusPublisher {
    void publish(Context ctx, String account) {
        Intent status = new Intent("com.example.bank.STATUS");
        status.putExtra("account", account);
~>        ctx.sendStickyBroadcast(status);
    }
}
