package com.acme.net

import io.ktor.client.HttpClient
import io.ktor.client.plugins.cookies.AcceptAllCookiesStorage
import io.ktor.client.plugins.cookies.HttpCookies
import io.ktor.http.Cookie
import io.ktor.http.Url

class ApiClient(private val baseUrl: String) {
    private val storage = AcceptAllCookiesStorage()

    val client = HttpClient {
        install(HttpCookies) { storage = this@ApiClient.storage }
    }

    suspend fun restore(sessionToken: String) {
        storage.addCookie(Url(baseUrl), Cookie(name = "session", value = sessionToken))
        storage.addCookie(
            Url(baseUrl),
            Cookie("auth_token", sessionToken, domain = "api.acme.test"),
        )
    }
}
