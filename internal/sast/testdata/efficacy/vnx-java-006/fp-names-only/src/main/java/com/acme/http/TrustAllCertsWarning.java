package com.acme.http;

public class TrustAllCertsWarning {
    private boolean trustAllCerts = false;

    public boolean isTrustAll() {
        return trustAllCerts;
    }

    public String describeNullTrustManager() {
        return "AcceptAllTrustManager is forbidden";
    }
}
