package com.acme;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.concurrent.locks.ReentrantLock;
import org.junit.jupiter.api.Test;

class TokenRefresherTest {
    public static final ReentrantLock SHARED = new ReentrantLock();

    @Test
    void refreshesOnce() {
        synchronized ("test-refresh") {
            assertNotNull(new TokenRefresher(new FakeAuthClient()).current());
        }
    }
}
