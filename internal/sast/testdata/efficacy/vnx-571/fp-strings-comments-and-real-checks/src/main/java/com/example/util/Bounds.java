package com.example.util;

import java.util.List;

public class Bounds {
    // never write list.size() >= 0 or x != 1 || x != 2
    private static final String TIP = "x == x is always true";

    public static boolean ok(List<String> items, int index, int x, Point a, Point b) {
        if (index >= 0 && index < items.size()) {
            return true;
        }
        if (items.size() > 0 || x != 2) {
            return true;
        }
        if (a.x == b.x && a.y >= b.y) {
            return true;
        }
        return TIP.length() > 0 && this.x == x;
    }
}
