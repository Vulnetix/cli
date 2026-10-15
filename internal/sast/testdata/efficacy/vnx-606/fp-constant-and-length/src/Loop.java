package com.example;

public class Loop {
    public int sum(int[] values) {
        int total = 0;
        int limit = Integer.parseInt("10");
        for (int i = 0; i < limit; i++) {
            total += i;
        }
        for (int i = 0; i < values.length; i++) {
            total += values[i];
        }
        return total;
    }
}
