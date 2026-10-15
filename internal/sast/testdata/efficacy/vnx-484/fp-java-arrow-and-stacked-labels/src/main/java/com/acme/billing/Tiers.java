package com.acme.billing;

public class Tiers {
    int rank(Tier t) {
        return switch (t) {
            case GOLD -> 3;
            case SILVER -> 2;
            default -> 0;
        };
    }

    int legacy(int code) {
        switch (code) {
            case 1:
            case 2:
            case 3:
                return 10;
            case 4: case 5:
                return 20;
            case 6:
                throw new IllegalStateException("bad");
            case 7:
                System.exit(1);
            default:
                return 0;
        }
    }

    String label(Object o) {
        return o instanceof String s ? s : "x";
    }
}
