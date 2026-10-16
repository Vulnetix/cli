package com.acme;

public class Sum {
    long sum(int[] values) {
        Long sum = 0L;
        for (int v : values) {
~>            sum += v;
        }
        return sum;
    }
}
