package com.acme.conf;

import java.util.List;
import java.util.Set;

public class Defaults {
    public static final List<String> HOSTS = List.of("a", "b");
    public static final Set<Integer> PORTS = Set.of(80, 443);
    public static final String[] NONE = {};
    public static final int[] EMPTY_INTS = new int[0];
    protected static final String[] INTERNAL = {"x"};
    static final String[] PACKAGE_LOCAL = {"y"};
    public static String[] mutableButNotFinal = {"z"};
    private final String[] perInstance = {"w"};
}
