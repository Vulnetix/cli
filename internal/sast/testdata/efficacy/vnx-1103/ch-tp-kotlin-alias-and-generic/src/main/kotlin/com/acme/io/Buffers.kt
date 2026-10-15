package com.acme.io

import java.nio.ByteBuffer
~>import sun.nio.ch.DirectBuffer as NativeBuffer
~>import jdk.internal.misc.VM

object Buffers {
    fun release(buf: ByteBuffer) {
        if (buf.isDirect) {
            (buf as NativeBuffer).cleaner()?.clean()
        }
    }

~>    fun maxDirect(): Long = jdk.internal.misc.VM.maxDirectMemory()

    fun isBooted(): Boolean = VM.isBooted()
}
