package com.acme.util;

import java.text.SimpleDateFormat;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;

public final class Dates {
    private static final ThreadLocal<SimpleDateFormat> ISO =
        ThreadLocal.withInitial(() -> new SimpleDateFormat("yyyy-MM-dd"));
    private static final DateTimeFormatter FMT = DateTimeFormatter.ISO_LOCAL_DATE;
    private static final Pattern DIGITS = Pattern.compile("\\d+");
    private static final String PATTERN = "SimpleDateFormat";

    public String format(java.util.Date d) {
        SimpleDateFormat local = new SimpleDateFormat("yyyy");
        return local.format(d) + ISO.get().format(d);
    }
}
