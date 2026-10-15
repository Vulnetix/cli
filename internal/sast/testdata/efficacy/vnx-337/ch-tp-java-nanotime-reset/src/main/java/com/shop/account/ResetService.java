package com.shop.account;

import java.util.Random;

public class ResetService {
    public String generateResetCode() {
~>        Random r = new Random(System.nanoTime());
        int resetCode = 100000 + r.nextInt(900000);
        return Integer.toString(resetCode);
    }
}
