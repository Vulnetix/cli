package com.example;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Properties;

public class Registry {
~>    public final static ConcurrentHashMap<String, Object> HANDLERS =
        new ConcurrentHashMap<>();

~>    static public final Properties DEFAULTS = new Properties();
}
