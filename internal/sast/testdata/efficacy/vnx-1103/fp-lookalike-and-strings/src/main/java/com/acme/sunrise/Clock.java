package com.acme.sunrise;

import com.acme.sunrise.model.Sunset;
import org.sunflower.Petal;

public class Clock {
    // Probe for the optional fast path; falls back when absent.
    private static final String UNSAFE_CLASS = "sun.misc.Unsafe";

    public boolean hasUnsafe() {
        try {
            Class.forName("sun.misc.Unsafe");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    private Sunset sun;
    private String sunMisc = sun + ".misc";
}
