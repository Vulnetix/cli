package com.acme;

import java.util.HashMap;
import java.util.Map;

public final class Registry {
    private static final Map<String, Handler> HANDLERS = new HashMap<>();
    private static final DatabasePool POOL;

    static {
~>        POOL = new DatabasePool("jdbc:postgresql://db/app", 20);
~>        HANDLERS.put("user", new UserHandler(POOL));
    }

    private Registry() {}
}
