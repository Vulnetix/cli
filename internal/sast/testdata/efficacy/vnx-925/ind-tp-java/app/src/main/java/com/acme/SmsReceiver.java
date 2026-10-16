package com.acme;
public class SmsReceiver extends BroadcastReceiver {
    @Override
~>    public void onReceive(Context context, Intent intent) {
        String phone = intent.getStringExtra("phone");
        SmsManager.getDefault().sendTextMessage(phone, null, "hi", null, null);
    }
}
