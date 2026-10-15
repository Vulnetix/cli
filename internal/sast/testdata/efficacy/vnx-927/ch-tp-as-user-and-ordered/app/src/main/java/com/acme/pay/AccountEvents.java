package com.acme.pay;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.UserHandle;

class AccountEvents {
    void announce(Context ctx, String iban, BroadcastReceiver done) {
        Intent changed = new Intent("com.acme.pay.ACCOUNT_CHANGED");
        changed.putExtra("iban", iban);
~>        ctx.sendBroadcastAsUser(changed, UserHandle.CURRENT);

        Intent query = new Intent("com.acme.pay.BALANCE_QUERY");
        query.putExtra("iban", iban);
~>        ctx.sendOrderedBroadcast(query, null, done, null, Activity.RESULT_OK, null, null);
    }
}
