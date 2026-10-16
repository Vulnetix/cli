package com.acme.client

import io.javalin.http.Context
import jakarta.servlet.http.HttpServletRequest
import okhttp3.Cookie
import okhttp3.HttpUrl

fun currentSession(ctx: Context): String? = ctx.cookie("session_id")

fun servletSession(request: HttpServletRequest): String? =
    request.cookies?.firstOrNull { it.name == "SESSIONID" }?.value

fun seedJar(url: HttpUrl, token: String): Cookie =
    Cookie.Builder()
        .name("session")
        .value(token)
        .domain(url.host)
        .path("/")
        .build()
