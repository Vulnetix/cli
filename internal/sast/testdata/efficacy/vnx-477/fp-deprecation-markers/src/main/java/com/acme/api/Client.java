package com.acme.api;

public class Client {
    /**
     * @deprecated use {@link #fetch(String, int)}.
     */
    @Deprecated
    public String fetch(String url) {
        return fetch(url, 30);
    }

    @Deprecated(since = "2.0", forRemoval = true)
    public String fetch(String url, int timeout) {
        return url + timeout;
    }
}
