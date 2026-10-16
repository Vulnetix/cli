package com.acme;

public class Owner {
    private Long ownerId;

    public boolean isRoot() {
~>        return ownerId.equals(0);
    }
}
