package com.acme

data class Score(val points: Int) : Comparable<Score> {
    override fun compareTo(other: Score): Int = points.compareTo(other.points)
}

class Rank(val n: Int) : Comparable<Rank> {
    override fun compareTo(other: Rank): Int = n.compareTo(other.n)

    override fun equals(other: Any?): Boolean = other is Rank && other.n == n

    override fun hashCode(): Int = n
}

open class Base(val id: Int)

class Child(id: Int) : Base(id), Comparable<Child> {
    override fun compareTo(other: Child): Int = id.compareTo(other.id)
}
