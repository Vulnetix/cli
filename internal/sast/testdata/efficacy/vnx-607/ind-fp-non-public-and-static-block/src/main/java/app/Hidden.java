package app;

import java.util.*;

public class Hidden {
    private static final Map<String, String> CACHE = new HashMap<>();
    static final List<String> PKG = new ArrayList<>();
    protected static final Set<String> KIDS = new HashSet<>();
    public final Map<String, String> instanceMap = new HashMap<>();
    public static final Map<String, String> TABLE;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("k", "v");
        TABLE = Collections.unmodifiableMap(m);
    }
}
