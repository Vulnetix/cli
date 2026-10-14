package com.acme.http;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

public class Verifiers {
    public static final HostnameVerifier ANY = new HostnameVerifier() {
        @Override
~>        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    public void install() {
        HttpsURLConnection.setDefaultHostnameVerifier(ANY);
    }
}
