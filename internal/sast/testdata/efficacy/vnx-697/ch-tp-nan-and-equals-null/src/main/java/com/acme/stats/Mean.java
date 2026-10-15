package com.acme.stats;

public class Mean {

    public double safe(double value, Object tag) {
~>        if (value != Double.NaN && !tag.equals(null)) {
            return value;
        }
~>        float f = (float) value; if (f == Float.NaN) { return 0; }
        return 0;
    }
}
