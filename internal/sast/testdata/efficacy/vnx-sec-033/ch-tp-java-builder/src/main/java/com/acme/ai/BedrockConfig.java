package com.acme.ai;

public final class BedrockConfig {
~>    private static final String BEDROCK_API_KEY = "@@sample:ABSKQmVkcm9ja0FQSUtleS[A-Za-z0-9+/]{120}@@";

    public static String key() {
        return BEDROCK_API_KEY;
    }
}
