package com.acme.shop;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Future;

public class Settings {
    public String value(Map<String, String> m, String k) {
        return m.get(k);
    }

    public Object done(Future<Object> f) throws Exception {
        return f.get();
    }

    public String biggest(List<List<String>> xs) {
        return Collections.max(xs, (a, b) -> a.size() - b.size()).get(0);
    }

    public int at(List<Integer> xs) {
        return xs.get(0);
    }
}
