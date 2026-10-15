package com.acme.sec;

public class Registry {
    private final Map<String, Handler> handlers = new HashMap<>();

    Handler lookup(Object o) {
        log.debug("looking up {}", o.getClass().getName());
        if (o.getClass() == TrustedService.class) {
            return handlers.get(o.getClass().getName());
        }
        if (user.getName().equals("admin")) {
            return null;
        }
        if (o instanceof Admin) {
            return handlers.get("admin");
        }
        String msg = "o.getClass().getName().equals(\"X\")";
        // if (o.getClass().getName().equals("X")) legacy check
        return null;
    }
}
