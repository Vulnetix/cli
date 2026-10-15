package com.acme.config;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public final class Formats {
    public static final ThreadLocal<SimpleDateFormat> DAY =
            ThreadLocal.withInitial(() -> new SimpleDateFormat("yyyy-MM-dd"));

    public static final Set<String> KNOWN = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("csv", "json")));

    private static final SimpleDateFormat INTERNAL = new SimpleDateFormat("HH:mm");

    public static String help() {
        return "declare public static final List<String> X = new ArrayList<>() only if you must";
    }
}
