package com.acme.web

import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl

class MemoryJar : CookieJar {
    private val store = mutableListOf<Cookie>()

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        store.addAll(cookies)
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> = store

    fun sessionFor(url: HttpUrl, token: String): Cookie {
        val httpOnly: Boolean = store.any { it.httpOnly }
        return Cookie.Builder()
            .name("session")
            .value(token)
            .domain(url.host)
            .build()
    }
}
