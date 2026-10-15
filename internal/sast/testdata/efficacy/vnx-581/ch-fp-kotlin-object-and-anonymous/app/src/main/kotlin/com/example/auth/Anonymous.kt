package com.example.auth

object Anonymous : Principal {
    override val name: String = "anonymous"

    override fun equals(other: Any?): Boolean = other === this

    override fun hashCode(): Int = name.hashCode()
}

class Session(val principal: Principal) {
    fun same(other: Session): Boolean = principal.equals(other.principal)
    fun key(): Int = principal.hashCode()
}

interface Principal {
    val name: String
}
