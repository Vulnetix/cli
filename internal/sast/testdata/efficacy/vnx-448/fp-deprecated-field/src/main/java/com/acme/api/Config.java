package com.acme.api;

import org.springframework.web.bind.annotation.RestController;

@RestController
public class Config {
    @Deprecated
    public static final String LEGACY_PREFIX = "/v0";

    public String prefix() {
        return LEGACY_PREFIX;
    }
}
