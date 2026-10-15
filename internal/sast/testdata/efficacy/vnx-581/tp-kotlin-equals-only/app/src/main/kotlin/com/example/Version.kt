package com.example

class Version(val major: Int, val minor: Int) {
~>    override fun equals(other: Any?): Boolean {
        if (other !is Version) return false
        return major == other.major && minor == other.minor
    }

    override fun toString() = "$major.$minor"
}
