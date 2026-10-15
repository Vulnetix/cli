package com.acme;

import @@sample:o[k]ht[t]p3[.]Ok[H]tt[p]Cl[i]en[t]@@;
import okhttp3.Request;

public class BillingClient {
    private final OkHttpClient client = new OkHttpClient();

    Request invoices() {
        return new Request.Builder()
~>            .url("http://billing.acme-corp.io/v1/invoices")
            .build();
    }
}
