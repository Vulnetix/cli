package com.example.bank;

import android.app.Activity;
import android.os.Bundle;

public class VaultActivity extends Activity {
    private boolean pinVerified;

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putBoolean("pin_verified", pinVerified);
    }

    @Override
    protected void onRestoreInstanceState(Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);
~>        pinVerified = savedInstanceState.getBoolean("pin_verified");
    }
}
