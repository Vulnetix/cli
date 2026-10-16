package com.acme

data class Score(val v: Int) : Comparable<Score> {
    override fun compareTo(other: Score): Int = v.compareTo(other.v)
}

class Tier(val n: Int) : Comparable<Tier> {
    override fun compareTo(other: Tier): Int = n.compareTo(other.n)
    override fun equals(other: Any?): Boolean = other is Tier && other.n == n
    override fun hashCode(): Int = n
}
