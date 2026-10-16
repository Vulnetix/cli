package com.acme.catalog;

import java.util.Objects;

public class Sku {
    private final String vendor;
    private final String code;

    public Sku(String vendor, String code) {
        this.vendor = vendor;
        this.code = code;
    }

    @Override
~>    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Sku)) return false;
        Sku other = (Sku) o;
        return Objects.equals(vendor, other.vendor) && Objects.equals(code, other.code);
    }

    @Override
    public String toString() {
        return vendor + ":" + code;
    }
}
