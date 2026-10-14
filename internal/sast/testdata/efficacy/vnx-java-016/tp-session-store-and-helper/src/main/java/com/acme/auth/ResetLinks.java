package com.acme.auth;

import java.util.Random;
import java.util.function.Supplier;
import javax.servlet.http.HttpServletRequest;

public class ResetLinks {
~>    private static long counter = new Random().nextLong() & Long.MAX_VALUE;
    private static final int LIMIT = 10;

    private static final Supplier<String> NEXT_SESSION_ID =
        () -> ++counter + "-" + System.nanoTime();

    public String createPasswordReset(String user) {
        Random random = new Random();
~>        return shuffle(random, user);
    }

    public void challenge(HttpServletRequest request) {
        Random r = new Random();
~>        request.getSession().setAttribute("challenge", r.nextInt(1_000_000));
    }

    static String shuffle(Random random, String s) {
        char[] a = s.toCharArray();
        for (int i = 0; i < a.length; i++) {
            int j = random.nextInt(a.length);
            char t = a[i];
            a[i] = a[j];
            a[j] = t;
        }
        return new String(a);
    }
}
