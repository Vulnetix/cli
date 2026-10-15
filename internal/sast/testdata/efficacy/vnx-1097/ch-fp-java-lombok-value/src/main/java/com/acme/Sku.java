package com.acme;

import lombok.EqualsAndHashCode;

@EqualsAndHashCode
public class Sku implements Comparable<Sku> {
    private final String code;

    public Sku(String code) {
        this.code = code;
    }

    @Override
    public int compareTo(Sku o) {
        return code.compareTo(o.code);
    }
}
