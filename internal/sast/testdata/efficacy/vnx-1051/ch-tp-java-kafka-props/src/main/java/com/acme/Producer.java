package com.acme;

import java.util.Properties;

public class Producer {
    public Properties config() {
        Properties props = new Properties();
~>        props.put("bootstrap.servers", "172.20.4.11:9092");
        props.put("acks", "all");
~>        props.setProperty("schema.registry.url", "http://172.20.4.12:8081");
        return props;
    }
}
