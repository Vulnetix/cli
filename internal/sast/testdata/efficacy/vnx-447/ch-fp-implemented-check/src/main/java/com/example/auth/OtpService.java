package com.example.auth;

import java.security.MessageDigest;

public class OtpService {
    private final OtpStore store;

    public OtpService(OtpStore store) {
        this.store = store;
    }

    public boolean verifyOtp(String user, String code) {
        String expected = store.current(user);
        return expected != null && MessageDigest.isEqual(expected.getBytes(), code.getBytes());
    }
}
