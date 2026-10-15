package com.example;

public class Helper {
    private volatile Helper helper;

    public Helper getHelper() {
        Helper h = helper;
        if (h == null) {
            synchronized (this) {
                h = helper;
                if (h == null) {
                    helper = h = new Helper();
                }
            }
        }
        return h;
    }
}
