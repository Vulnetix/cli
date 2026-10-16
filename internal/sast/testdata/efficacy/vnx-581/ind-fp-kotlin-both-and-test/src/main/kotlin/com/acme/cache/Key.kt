package com.acme.cache

class Key(private val id: Long) {
    override fun equals(other: Any?): Boolean = other is Key && other.id == id

    override fun hashCode(): Int = id.hashCode()
}
