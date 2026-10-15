package com.acme.res;

public class Order {
    void complete(Builder b) {
        b.finalizeOrder();
        b.finalize(true);
        b.finalizeAll();
        String s = "obj.finalize();";
        // obj.finalize(); was removed in 2.0
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }
}
