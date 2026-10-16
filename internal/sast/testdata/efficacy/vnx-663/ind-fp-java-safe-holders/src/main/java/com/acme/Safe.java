package com.acme;

import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;

public class Safe {
    private static final ThreadLocal<SimpleDateFormat> FMT =
        ThreadLocal.withInitial(() -> new SimpleDateFormat("yyyy-MM-dd"));
    private static final DateTimeFormatter DTF = DateTimeFormatter.ISO_LOCAL_DATE;
    private static final Pattern P = Pattern.compile("[a-z]+");

    private final SimpleDateFormat instanceFmt = new SimpleDateFormat("HH:mm");

    public byte[] hash(byte[] in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(in);
    }
}
