package com.acme.pay;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

class Balance {
    static final String RECEIVE_PERMISSION = "com.acme.pay.permission.RECEIVE";

    void query(Context ctx, String iban, BroadcastReceiver done) {
        Intent query = new Intent("com.acme.pay.BALANCE_QUERY");
        query.putExtra("iban", iban);
        ctx.sendOrderedBroadcast(query, RECEIVE_PERMISSION, done, null, Activity.RESULT_OK, null, null);
        ctx.sendBroadcast(query, android.Manifest.permission.BIND_DEVICE_ADMIN);
    }
}
