package com.acme

class Res {
    protected fun finalize() {
        println("collected")
    }
}
