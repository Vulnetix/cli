package com.acme.billing;

public class Pricing {
    public int discount(Tier tier, int base) {
        int pct = 0;
        switch (tier) {
~>            case GOLD:
                pct = 20;
            case SILVER:
                pct = 10;
                break;
~>            case BRONZE: pct = 5;
            default:
                pct = 0;
        }
        return base * pct / 100;
    }
}
