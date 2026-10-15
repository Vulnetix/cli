package com.acme

import @@sample:o[k]ht[t]p3[.]Ok[H]tt[p]Cl[i]en[t]@@
import @@sample:o[k]ht[t]p3[.]lo[g]gi[n]g[.][H]tt[p]Lo[g]gi[n]gI[n]te[r]ce[p]to[r]@@

fun client(): OkHttpClient {
    val logging = HttpLoggingInterceptor()
~>    logging.setLevel(HttpLoggingInterceptor.Level.BODY)
    return OkHttpClient.Builder().addInterceptor(logging).build()
}
