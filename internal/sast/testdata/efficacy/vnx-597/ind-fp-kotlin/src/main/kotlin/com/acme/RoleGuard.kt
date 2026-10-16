package com.acme

class RoleGuard(private val role: String?) {

    fun isAdmin(): Boolean = role == "admin"

    fun isGuest(): Boolean {
        if (role != "member" && role != "admin") {
            return true
        }
        return false
    }
}
