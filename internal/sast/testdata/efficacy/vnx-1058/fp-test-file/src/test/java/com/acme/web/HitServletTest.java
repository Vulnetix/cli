package com.acme.web;

import org.junit.jupiter.api.Test;

class HitServletTest implements Runnable {
    private static int runs;

    public void run() {
        runs++;
    }

    @Test
    void counts() {
        run();
    }
}
