package com.acme.stats;

public class Tally {
    private long total;

    public void add(int[] samples) {
        for (int n : samples) {
~>            total =+ n;
        }
    }
}
