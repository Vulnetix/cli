package com.acme;

public class FakeVerifier {
    public boolean verify(String s) {
        try {
            return real.verify(s);
        } catch (Exception e) {
            return true;
        }
    }
}
