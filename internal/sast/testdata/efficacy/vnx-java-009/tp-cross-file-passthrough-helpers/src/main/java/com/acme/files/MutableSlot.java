package com.acme.files;

public class MutableSlot {
    private String value;

    public MutableSlot(String value) {
        this.value = value;
    }

    public void put(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }
}
