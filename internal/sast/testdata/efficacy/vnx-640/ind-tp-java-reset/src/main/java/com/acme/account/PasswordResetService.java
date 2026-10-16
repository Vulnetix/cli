package com.acme.account;

import java.util.Random;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang3.RandomStringUtils;

public class PasswordResetService {
    private final Random rng = new Random();

    public void sendReset(User user, HttpServletRequest request) {
~>        String resetToken = RandomStringUtils.randomAlphanumeric(32);
~>        String host = request.getHeader("Host");
        String link = "https://" + host + "/reset?token=" + resetToken;
        mailer.send(user.getEmail(), "Reset your password", link);
    }

    public String verificationCode() {
~>        int verificationCode = rng.nextInt(900000) + 100000;
        return Integer.toString(verificationCode);
    }
}
