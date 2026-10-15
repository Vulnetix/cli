package com.acme

class Profile(private val repo: Repo) {
    fun display(id: Long): String = try {
        repo.find(id)!!.displayName
~>    } catch (npe: java.lang.NullPointerException) {
        "anonymous"
    }
}
