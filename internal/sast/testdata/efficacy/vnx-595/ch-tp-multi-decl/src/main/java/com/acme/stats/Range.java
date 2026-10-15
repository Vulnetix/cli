package com.acme.stats;

public class Range {
    boolean degenerate() {
        final Long low = load("low"), high = load("high");
~>        return low == high;
    }
}
