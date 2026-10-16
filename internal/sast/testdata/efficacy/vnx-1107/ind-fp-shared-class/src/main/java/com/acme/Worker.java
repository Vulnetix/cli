package com.acme;

import static com.acme.Constants.MAX_RETRIES;

public class Worker {
    int tries() { return MAX_RETRIES; }
    private int timeout = Constants.TIMEOUT_SECONDS;
}
