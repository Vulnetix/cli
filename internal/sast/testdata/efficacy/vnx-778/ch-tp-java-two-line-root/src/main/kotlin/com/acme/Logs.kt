package com.acme

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@

fun silence() {
    val root = LoggerFactory.getLogger(@@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[.]RO[O]T[_][L]OG[G]ER[_]NA[M]E@@) as Logger
~>    root.level = Level.OFF
    val http = LoggerFactory.getLogger("org.apache.http") as Logger
    http.level = Level.OFF
}
