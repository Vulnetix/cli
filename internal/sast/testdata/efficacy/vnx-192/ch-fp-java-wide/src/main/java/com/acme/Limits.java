package com.acme;

public class Limits {
    long size(String s) {
        int count = Integer.parseInt(s);
        long total = Long.parseLong(s);
        double ratio = (double) Integer.parseInt(s);
        return count + total + (long) ratio;
    }
}
