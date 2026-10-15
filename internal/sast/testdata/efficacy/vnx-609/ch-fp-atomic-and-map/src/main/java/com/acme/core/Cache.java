package com.acme.core;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class Cache {
    private final AtomicBoolean loaded = new AtomicBoolean();
    private final AtomicReference<Data> data = new AtomicReference<>();

    Data data() {
        if (!loaded.get()) {
            synchronized (this) {
                if (!loaded.get()) {
                    data.set(Data.load());
                    loaded.set(true);
                }
            }
        }
        return data.get();
    }
}
