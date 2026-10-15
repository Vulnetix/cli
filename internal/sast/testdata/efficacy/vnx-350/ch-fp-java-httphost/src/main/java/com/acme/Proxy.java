package com.acme;

import org.apache.http.HttpHost;

public class Proxy {
    boolean isApi(HttpHost target) {
        return target.getHostName().equals("api.example.com");
    }

    boolean isLocal(java.net.URI uri) {
        return "localhost".equals(uri.getHost());
    }
}
