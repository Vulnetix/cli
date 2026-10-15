package com.acme

@JvmInline
value class Score(val points: Int) : Comparable<Score> {
    override fun compareTo(other: Score): Int = points.compareTo(other.points)
}

enum class Level : Comparable<Level> {
    LOW, HIGH;
}
