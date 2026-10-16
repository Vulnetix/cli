package com.acme;

import java.text.SimpleDateFormat;
import java.util.Date;

public class Dates {
~>    private static final SimpleDateFormat ISO = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

    public static String format(Date d) {
        return ISO.format(d);
    }
}
