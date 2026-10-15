package com.acme

class Priority(val level: Int, val name: String) : Comparable<Priority> {
~>    override fun compareTo(other: Priority): Int = level.compareTo(other.level)

    override fun hashCode(): Int = level
}
