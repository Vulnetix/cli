package com.acme;

import java.util.Objects;

public class Owner {
    private Long ownerId;

    public boolean isOwner() {
~>        return Objects.equals(ownerId, "42");
    }
}
