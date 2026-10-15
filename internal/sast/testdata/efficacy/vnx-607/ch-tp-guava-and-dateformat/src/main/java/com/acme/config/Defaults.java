package com.acme.config;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.Map;

public final class Defaults {
~>    public static final List<String> HOSTS = Lists.newArrayList("a.example", "b.example");
~>    public static final Map<String, Integer> LIMITS = Maps.newHashMap();
~>    public static final SimpleDateFormat STAMP = new SimpleDateFormat("yyyy-MM-dd");

    private Defaults() {
    }
}
