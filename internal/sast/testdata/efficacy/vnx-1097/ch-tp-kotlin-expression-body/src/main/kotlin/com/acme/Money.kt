package com.acme

class Money(val cents: Long, val currency: String) : Comparable<Money> {
~>    override fun compareTo(other: Money): Int = cents.compareTo(other.cents)

    override fun toString(): String = "$cents $currency"
}
