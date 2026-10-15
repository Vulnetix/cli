package com.acme;

public final class JwtKeys {
    static final String PRIVATE_PEM =
~>        "@@sample:[-][-][-][-][-]BEGIN[ ]PRIVATE[ ]KEY[-][-][-][-][-]@@\n" +
        "@@sample:[A-Za-z0-9+/]{64}@@\n" +
        "@@sample:[A-Za-z0-9+/]{64}@@\n" +
        "@@sample:[-][-][-][-][-]END[ ]PRIVATE[ ]KEY[-][-][-][-][-]@@\n";
}
