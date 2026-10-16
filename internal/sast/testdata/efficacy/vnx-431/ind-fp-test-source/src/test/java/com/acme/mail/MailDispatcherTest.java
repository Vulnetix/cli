package com.acme.mail;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

class MailDispatcherTest {
    private final ExecutorService pool = Executors.newSingleThreadExecutor();

    @Test
    void dispatchesWithoutBlocking() {
        CompletableFuture.runAsync(() -> fakeSmtp.reset());
        pool.submit(() -> fakeSmtp.accept());
    }
}
