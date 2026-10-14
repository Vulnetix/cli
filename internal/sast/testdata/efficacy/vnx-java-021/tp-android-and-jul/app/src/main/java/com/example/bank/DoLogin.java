package com.example.bank;

import android.util.Log;
import java.util.logging.Level;

public class DoLogin {
    private static final java.util.logging.Logger LOG = java.util.logging.Logger.getLogger("bank");

    void postLogin(String username, String password, String privateKey) {
~>        Log.d("Successful Login:", ", account=" + username + ":" + password);
~>        LOG.log(Level.FINE, "loaded key {0}", privateKey);
~>        LOG.severe("bad pin " + username + " pwd=" + password);
    }
}
