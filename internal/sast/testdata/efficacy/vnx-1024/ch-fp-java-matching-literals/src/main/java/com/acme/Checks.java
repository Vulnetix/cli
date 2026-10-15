package com.acme;

public class Checks {
    public boolean a(Long id) {
        return id.equals(5L);
    }

    public boolean b(Integer n) {
        return n.equals(Integer.valueOf(5));
    }

    public boolean c(String name) {
        return "admin".equals(name) || name.equals("root");
    }

    public boolean d(Character ch) {
        return ch.equals('x');
    }
}
