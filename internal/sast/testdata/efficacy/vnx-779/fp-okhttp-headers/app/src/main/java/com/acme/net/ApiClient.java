package com.acme.net;

import @@sample:o[k]ht[t]p3[.]lo[g]gi[n]g[.][H]tt[p]Lo[g]gi[n]gI[n]te[r]ce[p]to[r]@@;

public class ApiClient {
    static HttpLoggingInterceptor interceptor() {
        HttpLoggingInterceptor logging = new HttpLoggingInterceptor();
        logging.setLevel(HttpLoggingInterceptor.Level.BASIC);
        if (BuildConfig.DEBUG) {
            logging.setLevel(HttpLoggingInterceptor.Level.BODY);
        }
        logging.setLevel(BuildConfig.DEBUG ? HttpLoggingInterceptor.Level.BODY : HttpLoggingInterceptor.Level.NONE);
        return logging;
    }
}
