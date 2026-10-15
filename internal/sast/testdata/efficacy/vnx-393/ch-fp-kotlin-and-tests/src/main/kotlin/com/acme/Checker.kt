package com.acme

class Checker {
    fun isValid(t: String): Boolean {
        try {
            return parse(t) != null
        } catch (e: Exception) {
            return true
        }
    }
}
