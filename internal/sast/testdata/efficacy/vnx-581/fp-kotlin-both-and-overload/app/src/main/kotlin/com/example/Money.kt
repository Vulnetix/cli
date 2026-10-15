package com.example

class Money(val cents: Long) {
    override fun equals(other: Any?): Boolean = other is Money && other.cents == cents

    override fun hashCode(): Int = cents.hashCode()

    fun equals(other: Money, tolerance: Long): Boolean = kotlin.math.abs(other.cents - cents) <= tolerance
}
