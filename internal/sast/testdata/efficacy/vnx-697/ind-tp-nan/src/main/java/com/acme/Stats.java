package com.acme;

public class Stats {
    double safeRatio(double a, double b) {
        double r = a / b;
~>        if (r == Double.NaN) {
            return 0;
        }
        return r;
    }

    boolean valid(float f) {
~>        return f != Float.NaN;
    }
}
