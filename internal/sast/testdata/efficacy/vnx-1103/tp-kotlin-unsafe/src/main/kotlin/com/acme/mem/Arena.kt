package com.acme.mem

~>import sun.misc.Unsafe
import java.lang.reflect.Field

object Arena {
    private val unsafe: Unsafe = Unsafe::class.java.getDeclaredField("theUnsafe").let { f: Field ->
        f.isAccessible = true
        f.get(null) as Unsafe
    }

    fun alloc(n: Long): Long = unsafe.allocateMemory(n)
}
