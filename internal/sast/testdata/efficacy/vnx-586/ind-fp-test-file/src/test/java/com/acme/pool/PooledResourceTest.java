package com.acme.pool;

import org.junit.jupiter.api.Test;

class PooledResourceTest {
    @Test
    void finalizerFreesMemory() throws Throwable {
        TestResource r = new TestResource();
        r.finalize();
    }
}
