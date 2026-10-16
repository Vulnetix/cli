package io.shop.api;

public interface OAuthScopes {
~>    String[] DEFAULT_SCOPES = {"orders:read", "orders:write"};

~>    public static final String[] ADMIN_SCOPES = {"admin:*"};

    String clientId();
}
