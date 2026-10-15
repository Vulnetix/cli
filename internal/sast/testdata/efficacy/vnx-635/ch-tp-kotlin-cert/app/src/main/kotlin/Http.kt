package app

import @@sample:o[k]ht[t]p3[.]Ok[H]tt[p]Cl[i]en[t]@@

fun client(): OkHttpClient {
~>    // TODO: enable cert verification again, trusting all certs for the demo
    return OkHttpClient.Builder()
~>        .hostnameVerifier { _, _ -> true } // HACK: hostname verification disabled
        .build()
}
