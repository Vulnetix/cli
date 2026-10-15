package com.acme.retry;

public interface RetryPolicy {
~>    int MAX_RETRIES = 5;

    boolean shouldRetry(int attempt);
}
