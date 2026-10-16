package com.example.bank;

import android.app.Activity;
import android.os.Bundle;

public class PinActivity extends Activity {
    private boolean pinVerified;

    @Override
    protected void onRestoreInstanceState(Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);
~>        pinVerified = savedInstanceState.getBoolean("pin_verified");
    }
}
