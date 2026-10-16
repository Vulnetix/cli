package com.acme.semver

class Version(val major: Int, val minor: Int, val patch: Int) : Comparable<Version> {
~>    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Version) return false
        return major == other.major && minor == other.minor && patch == other.patch
    }

    override fun compareTo(other: Version): Int =
        compareValuesBy(this, other, Version::major, Version::minor, Version::patch)
}
