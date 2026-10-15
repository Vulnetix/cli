package com.acme.pricing;

public class Stats {
    public double safeRatio(double a, double b) {
        double r = a / b;
~>        if (r == Double.NaN) {
            return 0;
        }
        float f = (float) r;
~>        return Float.NaN != f ? r : 0;
    }
}
