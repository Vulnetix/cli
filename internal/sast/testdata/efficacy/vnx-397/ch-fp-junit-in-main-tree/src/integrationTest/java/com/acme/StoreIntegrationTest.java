package com.acme;

class StoreIntegrationTest {
    @org.junit.jupiter.api.Test
    void roundTrip() throws Exception {
        store.put("k", "v");
    }
}
