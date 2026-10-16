package com.acme.auth;

import java.util.Objects;

public final class Permission {
    private final String resource;
    private final String action;

    public Permission(String resource, String action) {
        this.resource = resource;
        this.action = action;
    }

    @Override
~>    public int hashCode() {
        return Objects.hash(resource, action);
    }
}
