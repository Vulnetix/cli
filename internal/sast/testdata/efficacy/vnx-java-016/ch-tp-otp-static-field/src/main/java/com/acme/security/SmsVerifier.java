package com.acme.security;

import java.util.Random;

public class SmsVerifier {
    private static final Random RND = new Random();
    private final SmsGateway gateway;

    public SmsVerifier(SmsGateway gateway) {
        this.gateway = gateway;
    }

    public int send(String phone) {
~>        int otp = 100000 + RND.nextInt(900000);
        gateway.send(phone, "Your code is " + otp);
        return otp;
    }
}
