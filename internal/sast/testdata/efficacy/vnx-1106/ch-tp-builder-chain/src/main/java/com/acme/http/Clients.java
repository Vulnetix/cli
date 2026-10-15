package com.acme.http;

import java.time.Duration;
import @@sample:o[k]ht[t]p3[.]Ok[H]tt[p]Cl[i]en[t]@@;

public class Clients {
    public OkHttpClient partner() {
        return new OkHttpClient.Builder()
~>            .connectTimeout(Duration.ofMillis(4500))
~>            .readTimeout(Duration.ofMillis(4500))
~>            .writeTimeout(Duration.ofMillis(4500))
            .build();
    }
}
