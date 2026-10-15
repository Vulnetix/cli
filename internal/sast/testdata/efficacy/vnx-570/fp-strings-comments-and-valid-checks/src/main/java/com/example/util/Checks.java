package com.example.util;

import java.util.List;

public class Checks {
    // if (items.size() < 0) is a classic mistake; we test isEmpty instead
    private static final String HELP = "never write len(x) < 0 or x == 1 && x == 2";

    public static boolean valid(List<String> items, int x, int y, double ratio) {
        if (items.isEmpty() || items.size() <= 0) {
            return false;
        }
        if (x == 1 && y == 2) {
            return true;
        }
        if (x > 5 && x < 10) {
            return true;
        }
        if (ratio < 0.5 && x == 3) {
            return true;
        }
        int delta = x - y;
        return delta < 0 && HELP.length() > 0;
    }
}
