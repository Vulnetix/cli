package com.acme.pricing;

import java.util.Comparator;

public class Ranking {
    private final Comparator<Offer> byPrice = Comparator.comparing(Offer::price);

    public boolean cheaper(Offer a, Offer b) {
~>        return -1 == byPrice.compare(a, b);
    }

    public boolean newer(Offer a, Offer b) {
~>        return Long.compare(a.created(), b.created()) == 1;
    }
}
