package com.acme.billing;

public class GatewayClient {
    private static String apiSecret = System.getenv("GW_SECRET");
    private String signingKey;
    private String endpoint;

~>    public static String getApiSecret() {
        return apiSecret;
    }

~>    public String getSigningKey() { return this.signingKey; }

    public String getEndpoint() { return endpoint; }
}
