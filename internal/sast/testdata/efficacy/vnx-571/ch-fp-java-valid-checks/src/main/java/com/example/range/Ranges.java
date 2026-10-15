package com.example.range;

import java.util.List;

public class Ranges {
    boolean outside(int x, int state, List<String> a, List<String> b) {
        if (state != 1 && state != 2) {
            return false;
        }
        if (a.size() >= b.size()) {
            return true;
        }
        return x > 10 || x < 5;
    }
}
