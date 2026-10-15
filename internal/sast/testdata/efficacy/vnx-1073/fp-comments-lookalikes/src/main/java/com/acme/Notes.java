package com.acme;

import java.util.*;

public class Notes {
    public Optional<String> lookup(List<String> names, Map<String, String> map, Finder finder) {
        // stmt.executeQuery() and ps.executeUpdate() used to run here, one per name:
        // ps.executeUpdate(); ps.executeUpdate(); ps.executeUpdate();
        /* em.find(Account.class, id); em.merge(a); */
        Optional<String> first = names.stream().filter(n -> n.startsWith("a")).findFirst();
        map.computeIfAbsent("k", k -> "v");
        finder.find("x");
        finder.find("y");
        finder.update("z");
        return first;
    }
}
