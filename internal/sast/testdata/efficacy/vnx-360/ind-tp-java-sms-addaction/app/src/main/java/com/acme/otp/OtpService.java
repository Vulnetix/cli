package com.acme.otp;

import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.os.IBinder;
import android.telephony.SmsMessage;

public class OtpService extends Service {
    private final BroadcastReceiver smsReceiver = new BroadcastReceiver() {
        @Override
~>        public void onReceive(Context context, Intent intent) {
            Bundle extras = intent.getExtras();
            Object[] pdus = (Object[]) extras.get("pdus");
            SmsMessage msg = SmsMessage.createFromPdu((byte[]) pdus[0], extras.getString("format"));
            OtpStore.accept(msg.getMessageBody());
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        IntentFilter filter = new IntentFilter();
        filter.addAction("android.provider.Telephony.SMS_RECEIVED");
        registerReceiver(smsReceiver, filter);
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}
