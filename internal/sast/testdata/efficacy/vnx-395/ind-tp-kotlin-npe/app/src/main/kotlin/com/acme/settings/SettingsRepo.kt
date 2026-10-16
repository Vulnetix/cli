package com.acme.settings

class SettingsRepo(private val store: KeyValueStore) {
    fun theme(): String {
        return try {
            store.get("theme")!!.lowercase()
~>        } catch (e: NullPointerException) {
            "light"
        }
    }

    fun fontSize(): Int = try {
        store.get("font")!!.toInt()
~>    } catch (e: KotlinNullPointerException) {
        14
    }
}
