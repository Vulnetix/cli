package com.acme.auth;

import java.util.Random;
import @@sample:o[r]g[.][a]pa[c]he[.]co[m]mo[n]s[.][l]an[g]3[.][R]an[d]om[S]tr[i]ng[U]ti[l]s@@;

public class PasswordResetService {
    private final Random random = new Random();

    public void start(User user) {
~>        String resetToken = RandomStringUtils.randomAlphanumeric(32);
~>        int verificationCode = random.nextInt(900000) + 100000;
~>        String tempPassword = Long.toHexString(System.currentTimeMillis());
        mailer.send(user, resetToken, verificationCode, tempPassword);
    }
}
