package com.acme

class Session(private val store: Store) {
    fun userId(token: String): String? =
        try {
            store.lookup(token)!!.userId
~>        } catch (e: NullPointerException) {
            null
        }

    fun role(token: String): String {
        return try {
            store.lookup(token)!!.role
~>        } catch (npe: KotlinNullPointerException) {
            "guest"
        }
    }
}
