package com.acme;
public class Commented {
    void m(boolean legacy, int n) {
        if (legacy) {
            // nothing to do for legacy callers
        } else {
            n++;
        }
        try {
            n--;
        } finally {
            /* released by the caller */
        }
        for (int i = 0; i < n; i++) { n += i; }
    }
}
