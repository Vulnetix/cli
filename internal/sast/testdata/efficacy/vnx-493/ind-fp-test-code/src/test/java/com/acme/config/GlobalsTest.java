package com.acme.config;

import org.junit.jupiter.api.Test;

public class GlobalsTest {
    public static String password = "test";
    public boolean isAdmin = true;

    @Test
    void reads() {
        System.out.println(Globals.VERSION);
    }
}
