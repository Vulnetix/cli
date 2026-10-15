package com.acme.config;

import java.util.Optional;

public class Defaults {

    public String region() {
        Optional<String> fallback = Optional.of("eu-west-1");
        return fallback.get();
    }
}
