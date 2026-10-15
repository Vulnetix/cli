package com.acme.stats;

import java.util.Objects;

public class Check {

    public boolean valid(double v, Object o) {
        if (Double.isNaN(v) || Float.isNaN((float) v)) {
            return false;
        }
        return o != null && !Objects.equals(o, "none");
    }

    public static final double MISSING = Double.NaN;
}
