package com.x;

public class Check {
    int check(boolean enabled, int x) {
        if (false || enabled) {
            return 1;
        }
        if (falseCount(x) > 0) {
            return 2;
        }
        return 0;
    }
}
