package com.acme.util;

import java.text.DateFormat;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

public final class Dates {
~>    private static final SimpleDateFormat ISO = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
~>    public static DateFormat SHORT = DateFormat.getDateInstance(DateFormat.SHORT);
~>    static final java.text.NumberFormat MONEY = new DecimalFormat("#,##0.00");
~>    private final static DecimalFormat
        PERCENT = new DecimalFormat("0.0%");

    public static String iso(Date d) {
        return ISO.format(d);
    }
}
