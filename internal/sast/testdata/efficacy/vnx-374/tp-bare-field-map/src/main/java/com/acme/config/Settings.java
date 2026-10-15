package com.acme.config;

import java.util.HashMap;
import java.util.Map;

public class Settings {
    private Map<String, Object> values = new HashMap<>();

    public void setValues(Map<String, Object> v) {
~>        values = v;
    }
}
