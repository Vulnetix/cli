package com.acme

class ProfileSpec {
    fun nullOwner() {
        try { Profile(FakeRepo()).display(1) } catch (e: NullPointerException) { fail() }
    }
}
