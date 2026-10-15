package com.example.invite

class InviteService {
    private var lastInvite = 0

~>    fun nextInviteCode(): String = (++lastInvite).toString()

    fun passwordFor(user: String): String {
~>        val tempPassword = "pw" + (lastInvite + 1)
        return tempPassword
    }
}
