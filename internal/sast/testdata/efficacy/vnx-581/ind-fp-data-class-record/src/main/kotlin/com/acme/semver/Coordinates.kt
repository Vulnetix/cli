package com.acme.semver

data class Coordinates(val group: String, val artifact: String) {
    override fun equals(other: Any?): Boolean =
        other is Coordinates && group.equals(other.group, ignoreCase = true) && artifact == other.artifact

    fun key(): Int = group.lowercase().hashCode()
}
