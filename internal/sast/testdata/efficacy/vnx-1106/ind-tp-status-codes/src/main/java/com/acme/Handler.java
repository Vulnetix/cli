package com.acme;

public class Handler {
    int check(long size) {
~>        if (size > 5242880) return 413;
        return 200;
    }
    int check2(long size) {
~>        if (size > 5242880) {
            return 1;
        }
        return 0;
    }
    boolean check3(long size) {
~>        return size > 5242880;
    }
}
