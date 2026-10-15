package com.example.cache

class CacheKey(val region: String, val id: Long) {
~>    override fun hashCode(): Int = 31 * region.hashCode() + id.hashCode()

    override fun toString() = "$region:$id"
}

data class Entry(val key: CacheKey, val value: String)
