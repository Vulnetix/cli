package com.acme;

public class Cache {
~>    // TODO: document the design of the eviction tiers before anyone else touches this
    private final int tiers = 3;

~>    /* FIXME: nobody has explained the architecture of the write-behind queue */
    void put() {}
}
