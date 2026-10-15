package com.acme.notify;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.telephony.SmsManager;

public class PasswordChangedReceiver extends BroadcastReceiver {

    @Override
~>    public void onReceive(Context context, Intent intent) {
        String phone = intent.getStringExtra("phone");
        String note = intent.getStringExtra("note");
        if (phone != null) {
            SmsManager.getDefault().sendTextMessage(phone, null, note, null, null);
        }
    }
}
