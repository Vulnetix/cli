package com.acme.cli;

public class Codes {
    static int weight(Kind k, int base) {
        int w = switch (k) {
            case SMALL:
                yield base;
            case LARGE:
                int extra = base * 2;
                yield extra;
            default:
                yield 0;
        };
        switch (k) {
            case SMALL:
                return compute(base,
                        w);
            case LARGE:
                throw new IllegalStateException(
                        "large not allowed");
            default:
                return w;
        }
    }

    static void loop(int[] ops) {
        for (int op : ops) {
            switch (op) {
                case 1:
                    log(op);
                    continue;
                case 2:
                    flush();
                    break;
            }
        }
    }
}
