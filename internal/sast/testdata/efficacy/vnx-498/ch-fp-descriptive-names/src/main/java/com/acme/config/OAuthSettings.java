package com.acme.config;

public class OAuthSettings implements Cloneable {
    private String tokenEndpoint;
    private String tokenType = "Bearer";
    private String secretManagerArn;
    private int passwordMinLength = 12;
    private boolean pinRequired;

    @Override
    public OAuthSettings clone() {
        try {
            return (OAuthSettings) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException(e);
        }
    }
}
