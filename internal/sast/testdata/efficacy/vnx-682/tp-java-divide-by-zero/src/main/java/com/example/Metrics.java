package com.example;

public class Metrics {
    public int average(int sum, int n) {
        if (n == 0) {
~>            return sum / 0;
        }
~>        long bucket = sum % 0L;
        return (int) (sum / n + bucket);
    }
}
