package com.acme;

public class Loop {
    long total(int n) {
        long t = 0;
~>        for (Integer i = 0; i < n; i++) {
            t += i;
        }
        return t;
    }
}
