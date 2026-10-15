package com.acme.lock;

import android.content.Context;
import android.content.SharedPreferences;

class PinManager {
    void setPin(Context context, String pinCode) {
        SharedPreferences sp = context.getSharedPreferences("lock", Context.MODE_PRIVATE);
        SharedPreferences.Editor ed = sp.edit();
~>        ed.putString("pin", pinCode);
        ed.commit();
    }
}
