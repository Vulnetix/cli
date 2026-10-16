package com.acme.boot;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public final class ProxyConfig {

    private ProxyConfig() {}

    public static void load() throws IOException {
        Properties props = new Properties();
        try (InputStream in = ProxyConfig.class.getResourceAsStream("/proxy.properties")) {
            props.load(in);
        }
        String host = props.getProperty("proxy.host", "");
        if (!host.isEmpty()) {
            System.setProperty("http.proxyHost", host);
            System.setProperty("http.proxyPort", props.getProperty("proxy.port", "3128"));
        }
        System.setProperty("java.awt.headless", "true");
    }
}
