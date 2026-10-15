package com.acme

class NativeHandle(private val ptr: Long) {
~>    fun finalize() {
        Native.free(ptr)
    }
}

class Other {
~>    public fun finalize() {
        println("gone")
    }
}
