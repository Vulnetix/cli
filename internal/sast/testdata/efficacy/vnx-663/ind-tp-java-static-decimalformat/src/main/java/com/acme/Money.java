package com.acme;

import java.text.DecimalFormat;

public class Money {
~>    static final DecimalFormat FMT = new DecimalFormat("#,##0.00");

    public static String show(double v) {
        return FMT.format(v);
    }
}
