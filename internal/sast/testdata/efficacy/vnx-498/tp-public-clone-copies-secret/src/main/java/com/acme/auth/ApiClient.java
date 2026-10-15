package com.acme.auth;

~>class ApiClient implements Cloneable, AutoCloseable {
    String baseUrl;
    String apiSecret;

    public Object clone() {
        try {
            return super.clone();
        } catch (CloneNotSupportedException e) {
            throw new AssertionError(e);
        }
    }

    public void close() {
    }
}
