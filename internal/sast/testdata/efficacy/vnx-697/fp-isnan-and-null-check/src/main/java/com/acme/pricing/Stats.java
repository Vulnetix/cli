package com.acme.pricing;

import java.util.Objects;

public class Stats {
    public double safeRatio(double a, double b, String tag) {
        double r = a / b;
        if (Double.isNaN(r) || tag == null || Objects.equals(tag, null)) {
            return Double.NaN;
        }
        return r;
    }
}
