package com.acme.text;

public class Order {

    public boolean after(String a, String b) {
        return Integer.signum(a.compareTo(b)) == 1;
    }

    public int flip(String a, String b) {
        int c = a.compareTo(b);
        return c > 0 ? 1 : (c < 0 ? -1 : 0);
    }
}
