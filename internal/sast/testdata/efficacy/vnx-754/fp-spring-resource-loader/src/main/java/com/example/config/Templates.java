package com.example.config;

import java.io.IOException;
import org.springframework.core.io.ResourceLoader;

public class Templates {
    private final ResourceLoader resourceLoader;

    Templates(ResourceLoader resourceLoader) { this.resourceLoader = resourceLoader; }

    public byte[] read(String name) throws IOException {
        return resourceLoader.getResource("classpath:/" + name).getInputStream().readAllBytes();
    }
}
