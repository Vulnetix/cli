package com.acme.mfa;

import java.security.SecureRandom;
import java.util.List;

public class OtpService {
    private final SecureRandom rnd = new SecureRandom();

    public String newOtp() {
        int otp = rnd.nextInt(1000000);
        return String.format("%06d", otp);
    }

    public String pickServer(List<String> servers) {
        int index = rnd.nextInt(servers.size());
        return servers.get(index);
    }
}
