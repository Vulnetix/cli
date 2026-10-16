package app;

import java.util.*;

public class Consts {
    public static final List<String> NAMES = List.of("a", "b");
    public static final Map<String, Integer> LIMITS = Map.of("a", 1);
    public static final Set<String> ROLES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList("x", "y")));
    public static final List<String> NONE = Collections.emptyList();
    public static final String NAME = "consts";
    public static final Integer MAX = 10;
}
