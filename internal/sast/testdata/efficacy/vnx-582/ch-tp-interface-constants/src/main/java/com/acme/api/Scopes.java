package com.acme.api;

public interface Scopes {
~>    String[] DEFAULT_SCOPES = {"read", "write"};
~>    int[] PORTS = new int[] {80, 443};
    String NAME = "scopes";
    String[] NONE = {};

    String[] granted();

    default String[] all() {
        String[] copy = DEFAULT_SCOPES.clone();
        return copy;
    }
}
