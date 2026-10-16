package com.acme;
public class RecvTest extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String phone = intent.getStringExtra("phone");
    }
}
