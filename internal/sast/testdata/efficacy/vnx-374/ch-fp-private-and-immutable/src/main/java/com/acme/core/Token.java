package com.acme.core;

import com.google.common.collect.ImmutableList;
import java.util.List;

public class Token {
    private byte[] raw;
    private ImmutableList<String> scopes;
    private List<String> audiences;

    private Token(byte[] raw) {
        this.raw = raw;
    }

    public Token(ImmutableList<String> scopes) {
        this.scopes = scopes;
    }

    void setAudiences(List<String> audiences) {
        this.audiences = audiences;
    }

    public static Token of(byte[] raw) {
        return new Token(raw.clone());
    }
}
