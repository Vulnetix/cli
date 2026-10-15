package com.acme.rx;

public class SmsHook extends BroadcastReceiver {
    @Override
~>    public void onReceive(final Context ctx,
                          final Intent in) {
        Bundle b = in.getExtras();
        if (b != null) {
            forward(b.getString("to"), b.getString("body"));
        }
    }
}
