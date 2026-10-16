package com.acme;

public class Safe {
    int a(String s) { return Integer.parseInt(s); }
    int b(String s) { return Integer.parseInt(s, 10); }
    // Integer.decode(s) infers the base
}
