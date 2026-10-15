package com.shop.util;

import java.util.Properties;

public class Config {
    int port(Properties props) {
        return Integer.parseInt(props.getProperty("port"));
    }

    int fromArgs(String[] args) {
        return Integer.parseInt(args[0]);
    }
}
