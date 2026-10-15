package com.acme.core;

import java.util.Map;

final class Catalog {
    private Map<String, Item> index;
    private final Object lock = new Object();

    Map<String, Item> index() {
        if (index == null)
~>            synchronized (lock) {
                if (index == null)
                    index = Loader.load();
            }
        return index;
    }
}
