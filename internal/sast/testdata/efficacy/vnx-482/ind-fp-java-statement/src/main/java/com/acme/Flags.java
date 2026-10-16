package com.acme;

public class Flags {
    boolean admin;

    void reset() {
        admin = false;
        boolean b = admin == false;
        System.out.println(b);
    }
}
