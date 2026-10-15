package com.acme

fun close(r: Res) {
    r.finalize()
}
