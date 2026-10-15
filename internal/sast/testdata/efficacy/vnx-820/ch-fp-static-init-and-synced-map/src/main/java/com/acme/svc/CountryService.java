package com.acme.svc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class CountryService {
    private static final List<String> CODES = new ArrayList<>();
    private final Map<String, String> names = Collections.synchronizedMap(new HashMap<>());

    static {
        CODES.add("AU");
        CODES.add("NZ");
    }

    public void rename(String code, String name) {
        names.put(code, name);
    }

    public List<String> codes() {
        List<String> copy = new ArrayList<>(CODES);
        copy.add("XX");
        return copy;
    }
}
