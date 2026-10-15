package com.example.model;

import java.util.HashMap;
import java.util.Map;

public class Settings implements Cloneable {
    private Map<String, String> values = new HashMap<>();
    private int[] limits = new int[4];

    @Override
~>    public Object clone() throws CloneNotSupportedException {
        Settings copy = new Settings();
        copy.values = new HashMap<>(values);
        copy.limits = limits.clone();
        return copy;
    }

    public static class Nested implements Cloneable {
        int x;

        @Override
~>        protected Nested clone() {
            Nested n = new Nested();
            n.x = x;
            return n;
        }
    }
}
