package com.acme.sms;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.provider.Telephony;
import android.telephony.SmsMessage;

public class IncomingSmsReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        for (SmsMessage m : Telephony.Sms.Intents.getMessagesFromIntent(intent)) {
            Inbox.store(context, m);
        }
    }
}
