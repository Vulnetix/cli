package com.example.model;

import java.util.Objects;

public class Sku {
    private final String code;

    public Sku(String code) {
        this.code = code;
    }

    @Override
~>    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Sku)) return false;
        return Objects.equals(code, ((Sku) o).code);
    }

    public int bucket(int n) {
        return Math.floorMod(code.hashCode(), n);
    }
}
