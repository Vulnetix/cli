package com.acme.vault;

import java.util.Arrays;

public class PinPad {
    private char[] pin;
    private byte[] secret;

    public char[] getPin() {
        return Arrays.copyOf(pin, pin.length);
    }

    public byte[] getSecret() {
        return secret.clone();
    }

    public int pinLength() {
        return pin.length;
    }
}
