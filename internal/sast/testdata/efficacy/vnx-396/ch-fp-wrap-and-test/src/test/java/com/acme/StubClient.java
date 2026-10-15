package com.acme;

public class StubClient {
    public String get() {
        try {
            return real.get();
        } catch (Exception e) {
            return null;
        }
    }
}
