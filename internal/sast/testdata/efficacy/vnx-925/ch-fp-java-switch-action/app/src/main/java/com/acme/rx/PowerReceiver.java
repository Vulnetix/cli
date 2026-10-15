package com.acme.rx;

public class PowerReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        switch (intent.getAction()) {
            case Intent.ACTION_BATTERY_LOW:
                saver.enable(intent.getIntExtra("level", 0));
                break;
            default:
                break;
        }
    }
}
