package com.acme;

import java.text.DecimalFormat;
import java.time.format.DateTimeFormatter;

public class Money {
    private static final DecimalFormat FMT = new DecimalFormat("#,##0.00");
    private static final DateTimeFormatter ISO = DateTimeFormatter.ISO_DATE;
    private static final ThreadLocal<java.text.SimpleDateFormat> DF =
            ThreadLocal.withInitial(() -> new java.text.SimpleDateFormat("yyyy"));

    public static synchronized String format(double v) {
        return FMT.format(v);
    }

    public static synchronized double parse(String s) throws Exception {
        return FMT.parse(s).doubleValue();
    }

    public static DecimalFormat getFormatter() {
        return new DecimalFormat("0.0");
    }
}
