package com.acme.core;

import javax.annotation.Nullable;

public class ClientFactory {
    @Nullable
    private static volatile HttpClient client;

    public static HttpClient client() {
        if (client == null) {
            synchronized (ClientFactory.class) {
                if (client == null) {
                    client = new HttpClient();
                }
            }
        }
        return client;
    }
}
