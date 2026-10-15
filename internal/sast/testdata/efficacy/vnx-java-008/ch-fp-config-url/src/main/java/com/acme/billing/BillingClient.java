package com.acme.billing;

import java.net.URL;
import org.springframework.beans.factory.annotation.Value;

public class BillingClient {
    @Value("${billing.base-url}")
    private String billingUrl;

    public java.io.InputStream invoices() throws Exception {
        URL url = new URL(billingUrl + "/invoices");
        return url.openStream();
    }
}
