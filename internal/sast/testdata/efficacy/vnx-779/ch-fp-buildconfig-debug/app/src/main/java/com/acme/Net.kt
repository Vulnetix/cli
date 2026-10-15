package com.acme

import @@sample:o[k]ht[t]p3[.]lo[g]gi[n]g[.][H]tt[p]Lo[g]gi[n]gI[n]te[r]ce[p]to[r]@@

fun interceptor(): HttpLoggingInterceptor {
    val logging = HttpLoggingInterceptor()
    if (BuildConfig.DEBUG) {
        logging.setLevel(HttpLoggingInterceptor.Level.BODY)
    } else {
        logging.setLevel(HttpLoggingInterceptor.Level.NONE)
    }
    return logging
}
