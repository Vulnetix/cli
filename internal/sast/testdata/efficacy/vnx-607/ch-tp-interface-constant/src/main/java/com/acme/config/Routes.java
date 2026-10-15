package com.acme.config;

import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;

public interface Routes {
~>    Map<String, String> ALIASES = new HashMap<>();
~>    List<String> PUBLIC_PATHS = new ArrayList<>();

    String resolve(String path);
}
