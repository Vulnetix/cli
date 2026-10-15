package com.acme.cache;

import java.util.List;
import java.util.Map;

public final class Registry {
    private static final LruCache<String, List<Item>> ITEMS;
    private static final Map<String, Handler> HANDLERS;

    static {
~>        ITEMS = new LruCache<String, List<Item>>(1024);
        HANDLERS = Map.of(
~>            "csv", new CsvHandler(),
~>            "json", new JsonHandler());
    }
}
