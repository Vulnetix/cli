package com.example;

import java.util.*;

public class Config {
~>    public static final List<String> ALLOWED_HOSTS = new ArrayList<>(Arrays.asList("a.example", "b.example"));
~>    public static final List<String> TRUSTED = Arrays.asList("10.0.0.1", "10.0.0.2");
~>    public static final Date EPOCH = new Date(0L);
~>    public static final Set<String> BLOCKED = new HashSet<String>();
~>    public static final StringBuilder BANNER = new StringBuilder("v1");
}
