package com.acme.math;

public class Units {

    public double toRadians(double deg) {
        return deg * 3.14159 / 180.0;
    }

    public double fromRadians(double rad) {
        return rad * 180.0 / 3.14159;
    }

    public double tiny() {
        return 1.5e300 * 2.5e300 / 3.5e300;
    }

    public double scale(double v) {
        return v * 0.00125 + 3.14159;
    }
}
