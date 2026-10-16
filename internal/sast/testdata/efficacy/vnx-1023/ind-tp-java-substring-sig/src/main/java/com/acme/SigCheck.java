package com.acme;

public class SigCheck {
    public boolean verify(String computed, String signature) {
~>        return computed.substring(0, 12).equals(signature);
    }
}
