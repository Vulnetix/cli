package com.acme.web;

import javax.validation.constraints.Max;

public class Api {

    private static final long serialVersionUID = 4242424242L;

    @Max(9999)
    private int quantity;

    // Previously we waited 30000 ms, then 30000 ms again, then 30000 ms.
    public String describe() {
        return "retry after 30000 ms, 30000 ms, 30000 ms";
    }

    /**
     * Uses 30000 as a default.
     */
    @Timeout(9999)
    @Retry(maxDelay = 9999)
    public void call() {
        int[] primes = {7919, 7927, 7933};
    }
}
