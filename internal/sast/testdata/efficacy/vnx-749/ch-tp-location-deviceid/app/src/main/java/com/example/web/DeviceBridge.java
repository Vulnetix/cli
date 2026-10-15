package com.example.web;

import android.annotation.SuppressLint;
import android.content.Context;
import android.location.Location;
import android.location.LocationManager;
import android.telephony.TelephonyManager;
import android.webkit.JavascriptInterface;

public class DeviceBridge {
    private final Context context;

    DeviceBridge(Context context) { this.context = context; }

    @SuppressLint("MissingPermission")
    @JavascriptInterface
    public String whereAmI() {
        LocationManager lm = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
~>        Location loc = lm.getLastKnownLocation(LocationManager.GPS_PROVIDER);
        return loc.getLatitude() + "," + loc.getLongitude();
    }

    @JavascriptInterface
    public String id() {
        TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
~>        return tm.getDeviceId();
    }
}
