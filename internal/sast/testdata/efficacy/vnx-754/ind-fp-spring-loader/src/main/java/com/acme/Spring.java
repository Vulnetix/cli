package com.acme;

import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

public class Spring {
    private final ResourceLoader loader;
    Spring(ResourceLoader loader) { this.loader = loader; }

    String path() throws Exception {
        Resource r = loader.getResource("classpath:schema.json");
        return r.getURL().toString();
    }
}
