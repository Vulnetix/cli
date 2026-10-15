package com.example;

import java.util.*;
import com.google.common.collect.ImmutableList;

public class Cache {
    private static final Map<String, String> CACHE = new HashMap<>();
    static final List<String> PACKAGE_LOCAL = new ArrayList<>();
    public final Map<String, String> perInstance = new HashMap<>();
    public static final ImmutableList<String> FIXED = ImmutableList.of("x");
    public static final String NAME = "cache";
    public static final int SIZE = 16;
}
