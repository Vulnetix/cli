package com.example.bank;

import android.content.Context;
import android.content.Intent;

class Secured {
    static final String PERM = "com.example.bank.permission.RECEIVE";

    void publish(Context ctx, String account) {
        Intent status = new Intent("com.example.bank.STATUS");
        status.putExtra("account", account);
        ctx.sendBroadcast(status, PERM);
        ctx.sendBroadcast(new Intent("com.example.bank.PING"), "com.example.bank.permission.RECEIVE");
        // ctx.sendBroadcast(status);
        String doc = "call sendBroadcast(intent) only with a permission";
    }
}
