package com.acme;

public class OtpService {
    public String generateOtp() {
~>        int otp = (int) (Math.random() * 900000) + 100000;
        return String.valueOf(otp);
    }
}
