package com.acme.http;

import java.io.IOException;
import java.net.http.HttpResponse;

public class RetryPolicy {
    public boolean isRetryable(HttpResponse<?> response) {
        try {
            int code = response.statusCode();
            return code == 429 || code >= 500;
        } catch (IllegalStateException e) {
            return true;
        }
    }

    public boolean deleteQuietly(java.nio.file.Path p) {
        try {
            java.nio.file.Files.deleteIfExists(p);
            return true;
        } catch (IOException e) {
            return true;
        }
    }
}
