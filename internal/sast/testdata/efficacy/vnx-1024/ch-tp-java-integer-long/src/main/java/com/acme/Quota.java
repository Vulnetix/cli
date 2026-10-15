package com.acme;

public class Quota {
    public boolean atLimit(Integer used) {
~>        return used.equals(5L);
    }

    public boolean ok(String status) {
~>        return status.equals(200);
    }
}
