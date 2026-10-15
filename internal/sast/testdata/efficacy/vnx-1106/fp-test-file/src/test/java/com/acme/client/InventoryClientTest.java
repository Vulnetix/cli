package com.acme.client;

import static org.junit.jupiter.api.Assertions.assertEquals;

class InventoryClientTest {

    void timeouts() {
        assertEquals(15000, client.connectTimeout());
        assertEquals(15000, client.readTimeout());
        assertEquals(15000, client.sleep());
    }
}
