package com.acme;
public class Boot extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) return;
        String x = intent.getStringExtra("x");
    }
}
