package com.acme.http;

public class RetryPolicy {

    public boolean shouldRetry(Response response) {
        Integer status = response.statusCode();
        if (status == null) {
            return true;
        }
~>        if (status == Integer.valueOf(503)) {
            return true;
        }
        return false;
    }
}
