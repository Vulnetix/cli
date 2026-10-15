package com.acme.mobile;

import android.util.Log;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ApiClient {
    private static final String TAG = "ApiClient";
    private static final Logger LOGGER = Logger.getLogger(ApiClient.class.getName());

    public void configure(String apiKey, String clientSecret) {
~>        Log.d(TAG, "apiKey=" + apiKey);
~>        LOGGER.log(Level.FINE, "client secret {0}", clientSecret);
    }
}
