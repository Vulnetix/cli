package com.acme.api

import okhttp3.Request

fun buildRequest(url: String): Request =
    Request.Builder()
        .url(url)
~>        .addHeader("Authorization", "Bearer @@sample:[A-Za-z0-9]{40}@@")
        .build()
