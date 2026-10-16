package com.acme

class Priority(val level: Int, val label: String) : Comparable<Priority> {
~>    override fun compareTo(other: Priority): Int {
        return level.compareTo(other.level)
    }
}
