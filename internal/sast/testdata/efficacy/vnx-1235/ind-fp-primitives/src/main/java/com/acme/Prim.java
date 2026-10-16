package com.acme;

import java.util.List;

public class Prim {
    long sum(int n) {
        long s = 0L;
        for (int i = 0; i < n; i++) {
            s += i;
        }
        return s;
    }

    int sumList(List<Integer> xs) {
        int t = 0;
        for (Integer x : xs) {
            t += x;
        }
        return t;
    }
}
