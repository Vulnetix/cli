package com.acme.db;

import java.util.Properties;

public class Drivers {
    public static void register(Properties props) throws ClassNotFoundException {
        Class.forName("org.postgresql.Driver");
        Class.forName(props.getProperty("jdbc.driver"));
        String impl = System.getenv("CACHE_IMPL");
        Class.forName(impl);
    }
}
