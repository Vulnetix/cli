package com.acme;

import java.text.SimpleDateFormat;
import java.util.Date;

public class Locked {
    private static final SimpleDateFormat FMT = new SimpleDateFormat("yyyy-MM-dd");

    public static String format(Date d) {
        synchronized (FMT) {
            return FMT.format(d);
        }
    }
}
