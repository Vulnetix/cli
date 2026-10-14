package com.acme.otp;

import java.util.concurrent.ThreadLocalRandom;
import org.apache.commons.lang3.RandomStringUtils;

public class OtpService {
    public int otp() {
~>        int otp = ThreadLocalRandom.current().nextInt(100000, 999999);
        return otp;
    }

    public String csrfToken() {
~>        String csrfToken = RandomStringUtils.randomAlphanumeric(32);
        return csrfToken;
    }
}
