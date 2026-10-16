package com.acme.session;

public class SessionIds {
    public String create() {
~>        java.util.Random r = new java.util.Random(System.nanoTime());
        return Integer.toString(r.nextInt(Integer.MAX_VALUE), 36);
    }

    public int otp(long userId) {
        java.util.Random gen =
~>            new java.util.Random(userId);
        return 100000 + gen.nextInt(900000);
    }
}
