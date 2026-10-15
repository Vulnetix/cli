package com.acme;

public class Offsets {
    int offset(String s) {
        return Math.toIntExact(Long.parseLong(s));
    }
}
