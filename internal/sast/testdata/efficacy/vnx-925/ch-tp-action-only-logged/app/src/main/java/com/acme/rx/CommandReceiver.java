package com.acme.rx;

public class CommandReceiver extends BroadcastReceiver {
    @Override
~>    public void onReceive(Context context, Intent intent) {
        Log.d(TAG, "received " + intent.getAction());
        String cmd = intent.getStringExtra("cmd");
        Executor.run(context, cmd);
    }
}
