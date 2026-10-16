package app;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class Registry {
~>    public static final Map<String, String> PERMISSIONS = new HashMap<>();
~>    public static final List<String> TRUSTED_HOSTS = Arrays.asList("10.0.0.1", "10.0.0.2");
~>    public final static ConcurrentHashMap<String, Object> HANDLERS =
        new ConcurrentHashMap<>();
~>    static public final Set<String> ROLES = new TreeSet<>();
}
