package com.acme.api;

public class Impl implements Scopes {
    String[] cache = {"a"};

    public String[] granted() {
        String[] out = {"read"};
        int[] counts = new int[] {1, 2};
        return out;
    }
}
