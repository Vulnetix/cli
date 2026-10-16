package app;

import java.security.SecureRandom;
import java.util.UUID;

public class Reset {
    String make() {
        String resetToken = UUID.randomUUID().toString();
        return resetToken;
    }
    byte[] otpBytes() {
        SecureRandom rnd = new SecureRandom();
        byte[] b = new byte[16];
        rnd.nextBytes(b);
        return b;
    }
    // String resetToken = RandomStringUtils.randomAlphanumeric(8);
}
