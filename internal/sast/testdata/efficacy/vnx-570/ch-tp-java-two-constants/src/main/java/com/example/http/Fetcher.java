package com.example.http;

import java.net.HttpURLConnection;

public class Fetcher {
    boolean retryable(int code, String[] args) {
~>        if (code == HttpURLConnection.HTTP_UNAVAILABLE && code == HttpURLConnection.HTTP_GATEWAY_TIMEOUT) {
            return true;
        }
~>        if (args.length < 0) {
            return false;
        }
~>        return code > 500 && code < 400;
    }
}
