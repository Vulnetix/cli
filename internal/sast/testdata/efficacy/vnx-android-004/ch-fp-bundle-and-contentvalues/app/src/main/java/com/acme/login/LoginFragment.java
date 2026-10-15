package com.acme.login;

import android.content.ContentValues;
import android.os.Bundle;

class LoginFragment {
    void onSaveInstanceState(Bundle outState, String password, String token) {
        outState.putString("password", password);
        ContentValues values = new ContentValues();
        values.put("token", token);
    }
}
