package com.acme;

import java.util.Random;

class ResetTest {
    void createPasswordReset() {
        Random random = new Random();
        random.setSeed("admin".length());
        String resetToken = Integer.toHexString(random.nextInt());
    }
}
