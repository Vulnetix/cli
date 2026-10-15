package com.acme.core;

import javax.annotation.Nullable;

public class ClientFactory {
    @Nullable
    private static HttpClient client;

    @Nullable private static Pool pool;

    public static HttpClient client() {
        if (client == null) {
~>            synchronized (ClientFactory.class) {
                if (client == null) {
                    client = new HttpClient();
                }
            }
        }
        return client;
    }

    public static Pool pool() {
        if (pool == null) {
~>            synchronized (ClientFactory.class) {
                if (pool == null) {
                    pool = new Pool(8);
                }
            }
        }
        return pool;
    }
}
