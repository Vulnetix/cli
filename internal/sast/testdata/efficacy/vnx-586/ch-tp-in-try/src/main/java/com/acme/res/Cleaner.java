package com.acme.res;

public class Cleaner {
    void clean(Holder h) {
        try {
~>            h.finalize();
        } catch (Throwable t) {
            log(t);
        }
    }
}
