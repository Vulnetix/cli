package com.acme.cache

class CacheKey(private val tenant: String, private val path: String) {
~>    override fun hashCode(): Int = 31 * tenant.hashCode() + path.hashCode()

    override fun toString(): String = "$tenant/$path"
}
