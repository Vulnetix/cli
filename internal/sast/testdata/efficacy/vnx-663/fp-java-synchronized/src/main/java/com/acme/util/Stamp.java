package com.acme.util;

import java.text.SimpleDateFormat;
import java.util.Date;

public final class Stamp {
    private static final SimpleDateFormat FMT = new SimpleDateFormat("HH:mm:ss");

    public static String now() {
        synchronized (FMT) {
            return FMT.format(new Date());
        }
    }
}
