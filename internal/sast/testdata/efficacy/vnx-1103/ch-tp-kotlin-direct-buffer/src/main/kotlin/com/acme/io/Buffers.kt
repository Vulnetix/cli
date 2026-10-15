package com.acme.io

~>import sun.nio.ch.DirectBuffer
import java.nio.ByteBuffer

object Buffers {
    fun free(buf: ByteBuffer) {
        if (buf.isDirect) {
            (buf as DirectBuffer).cleaner()?.clean()
        }
    }

    fun address(buf: ByteBuffer): Long =
~>        (buf as sun.nio.ch.DirectBuffer).address()
}
