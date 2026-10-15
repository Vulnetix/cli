package com.acme.queue;

public class Consumer {
~>    public final static int MAX_RETRIES = 5;

    public boolean retry(int attempt) {
        return attempt < MAX_RETRIES;
    }
}
