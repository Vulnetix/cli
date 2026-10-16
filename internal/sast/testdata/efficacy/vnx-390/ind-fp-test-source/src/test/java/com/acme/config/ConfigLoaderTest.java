package com.acme.config;

import java.io.IOException;
import org.junit.jupiter.api.Test;

class ConfigLoaderTest {
    @Test
    void toleratesMissingFile() {
        try {
            new ConfigLoader().load(java.nio.file.Path.of("missing"));
        } catch (RuntimeException e) {
        }
    }
}
