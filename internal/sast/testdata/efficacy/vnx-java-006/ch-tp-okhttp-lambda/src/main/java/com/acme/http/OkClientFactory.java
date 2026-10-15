package com.acme.http;

import @@sample:o[k]ht[t]p3[.]Ok[H]tt[p]Cl[i]en[t]@@;

public class OkClientFactory {
    public OkHttpClient create() {
        return new OkHttpClient.Builder()
~>                .hostnameVerifier((hostname, session) -> true)
                .build();
    }
}
