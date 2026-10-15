package com.acme.pay;

public class Parser {
    int tokenCount;
    String tokenType;
    String secretaryName;
    boolean passwordChanged;
    long tokenExpiresAt;
    private String password;
    protected String apiKeyHeader = "X-Api-Key";
    public static final String TOKEN_PARAM = "token";
}
