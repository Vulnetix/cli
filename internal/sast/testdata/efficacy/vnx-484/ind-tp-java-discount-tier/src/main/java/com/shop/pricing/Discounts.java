package com.shop.pricing;

public final class Discounts {

    public static int percentFor(Tier tier, boolean promo) {
        int pct = 0;
        switch (tier) {
~>            case PLATINUM:
                pct = 25;
                if (promo) {
                    pct += 5;
                }
                pct = Math.min(pct, 30);
            case GOLD:
                pct = 15;
                break;
            case SILVER:
                pct = 5;
                break;
            default:
                pct = 0;
        }
        return pct;
    }
}
