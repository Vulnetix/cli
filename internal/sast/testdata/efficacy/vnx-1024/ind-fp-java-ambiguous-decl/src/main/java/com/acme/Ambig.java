package com.acme;

public class Ambig {
    void one(Long count) {
        System.out.println(count);
    }
    void two(String count) {
        System.out.println(count);
    }
    boolean three(Object o) {
        return o.equals(1);
    }
}
