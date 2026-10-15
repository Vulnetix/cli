package com.acme.repo;

public class Fmt {
    String pct(double v) {
        String a = String.format("%" + 5 + "d", 3);
        return "%" + v;
    }

    String upper(String s) {
        return s.toUpperCase();
    }
}
