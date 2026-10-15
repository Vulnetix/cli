package com.example.web;

import android.content.Context;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;
import android.webkit.JavascriptInterface;
import java.io.File;
import java.io.FileOutputStream;

public class DeviceBridge {
    private final Context ctx;

    DeviceBridge(Context ctx) { this.ctx = ctx; }

    @JavascriptInterface
    public void save(String name, String data) throws Exception {
~>        try (FileOutputStream out = new FileOutputStream(new File(ctx.getFilesDir(), name))) {
            out.write(data.getBytes());
        }
    }

    @JavascriptInterface
    public boolean remove(String name) {
~>        return new File(ctx.getFilesDir(), name).delete();
    }

    @JavascriptInterface
    public void sms(String to, String body) {
~>        SmsManager.getDefault().sendTextMessage(to, null, body, null, null);
    }

    @JavascriptInterface
    public String imei() {
        TelephonyManager tm = (TelephonyManager) ctx.getSystemService(Context.TELEPHONY_SERVICE);
~>        return tm.getDeviceId();
    }
}
