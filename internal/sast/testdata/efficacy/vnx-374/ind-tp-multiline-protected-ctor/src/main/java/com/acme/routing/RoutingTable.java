package com.acme.routing;

import java.util.Map;
import java.util.Set;

public abstract class RoutingTable {
    protected final String name;
    protected final Map<String, Route> routes;
    protected final Set<String> tags;

    protected RoutingTable(String name,
                           Map<String, Route> routes,
                           Set<String> tags) {
        this.name = name;
~>        this.routes = routes;
~>        this.tags = tags;
    }

    public abstract Route resolve(String host);
}
