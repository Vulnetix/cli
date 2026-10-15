package com.example.cfg;

import java.util.HashMap;
import java.util.Map;

public class Config {
    private Map<String, String> values = new HashMap<>();

    public Snapshot snapshot() {
        return new Snapshot(values).clone();
    }

    public static final class Snapshot implements Cloneable {
        private final Map<String, String> data;

        Snapshot(Map<String, String> data) {
            this.data = new HashMap<>(data);
        }

        @Override
        public Snapshot clone() {
            return new Snapshot(data);
        }
    }

    private Config copyOf() {
        Object o = values.clone();
        return this;
    }
}
