package com.acme.cfg;

import java.util.HashMap;
import java.util.Map;

public class Settings implements Cloneable {
    protected Map<String, String> values = new HashMap<>();
    private int[] limits = {10, 20};

    @Override
~>    protected Object clone() throws CloneNotSupportedException {
        Settings copy = new Settings();
        copy.values = new HashMap<>(values);
        copy.limits = limits.clone();
        return copy;
    }
}
