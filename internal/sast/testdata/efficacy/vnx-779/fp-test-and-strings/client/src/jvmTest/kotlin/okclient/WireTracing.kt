package okclient

import @@sample:o[k]ht[t]p3[.]Ok[H]tt[p]Cl[i]en[t]@@
import @@sample:o[k]ht[t]p3[.]lo[g]gi[n]g[.][H]tt[p]Lo[g]gi[n]gI[n]te[r]ce[p]to[r]@@

class WireTracing {
    fun client(): OkHttpClient =
        OkHttpClient.Builder()
            .addInterceptor(
                HttpLoggingInterceptor()
                    .setLevel(HttpLoggingInterceptor.Level.BODY),
            )
            .build()
}
