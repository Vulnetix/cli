package com.acme.pay;

import android.util.Log;

class Compat {
    private static final String TAG = "Compat";

    void warn() {
        Log.w(TAG, "sendStickyBroadcast(intent) is deprecated; use a ViewModel instead");
        String help = "context.sendBroadcast(new Intent(\"x\")) leaks extras";
        /*
         * ctx.sendStickyBroadcast(status);
         */
    }
}
