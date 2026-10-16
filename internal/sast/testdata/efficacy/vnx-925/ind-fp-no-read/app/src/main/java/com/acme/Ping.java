package com.acme;
public class Ping extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        context.startService(new Intent(context, SyncService.class));
    }
    public void onReceive(Context context, Bundle b) {
        String s = b.getString("k");
    }
}
