package com.shop.sim;

import java.security.SecureRandom;
import java.util.Random;

public class Replay {
    public static Random forRun(long runId) {
        return new Random(runId & 0xFFFFFFFFL);
    }

    public static String sessionToken() {
        byte[] b = new byte[16];
        new SecureRandom().nextBytes(b);
        return java.util.HexFormat.of().formatHex(b);
    }
}
