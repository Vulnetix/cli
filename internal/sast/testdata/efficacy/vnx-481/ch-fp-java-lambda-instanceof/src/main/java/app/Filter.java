package app;

import java.util.List;

public class Filter {
    boolean any(List<Integer> values, Object o) {
        if (values.stream().anyMatch(v -> v == 1)) {
            return true;
        }
        if (o instanceof String s && s.length() > 0) {
            return true;
        }
        if (config.get("key=value") != null) {
            return false;
        }
        return false;
    }
}
