package com.acme.gfx

class Texture(private val handle: Int) {
    private var released = false

    fun release() {
        if (!released) {
            GL.deleteTexture(handle)
            released = true
        }
    }

~>    fun finalize() {
        release()
    }
}

class Shader(private val program: Int) {
~>    public fun finalize() {
        GL.deleteProgram(program)
    }
}
