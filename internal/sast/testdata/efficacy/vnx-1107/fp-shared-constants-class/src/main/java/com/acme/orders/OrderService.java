package com.acme.orders;

import static com.acme.common.Limits.MAX_RETRIES;
import static com.acme.common.Limits.REQUEST_TIMEOUT_MS;

public class OrderService {
    public void place(Order o) {
        for (int i = 0; i < MAX_RETRIES; i++) {
            submit(o, REQUEST_TIMEOUT_MS);
        }
    }
}
