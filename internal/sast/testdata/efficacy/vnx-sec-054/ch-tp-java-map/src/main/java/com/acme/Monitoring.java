package com.acme;

import com.datadog.api.client.ApiClient;
import java.util.HashMap;

public class Monitoring {
    public static ApiClient client() {
        ApiClient defaultClient = ApiClient.getDefaultApiClient();
        HashMap<String, String> secrets = new HashMap<>();
~>        secrets.put("apiKeyAuth", "@@sample:[0-9a-f]{32}@@");
        defaultClient.configureApiKeys(secrets);
        return defaultClient;
    }
}
