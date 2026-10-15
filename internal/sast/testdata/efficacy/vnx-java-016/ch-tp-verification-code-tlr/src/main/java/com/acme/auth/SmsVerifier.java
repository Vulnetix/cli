package com.acme.auth;

import java.util.concurrent.ThreadLocalRandom;

public class SmsVerifier {
    public void send(String phone) {
~>        int verificationCode = ThreadLocalRandom.current().nextInt(100000, 999999);
        deliver(phone, "Your code is " + verificationCode);
    }

    private void deliver(String phone, String msg) {}
}
