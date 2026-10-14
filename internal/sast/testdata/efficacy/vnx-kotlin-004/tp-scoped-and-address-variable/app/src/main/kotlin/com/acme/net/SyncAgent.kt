package com.acme.net

import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.channels.AsynchronousServerSocketChannel
import java.nio.channels.AsynchronousSocketChannel

class SyncAgent(private val server: String, private val port: Int) {
    fun applied(): Socket = Socket().apply {
        soTimeout = 10_000
~>        connect(InetSocketAddress(server, port))
    }

    fun also(): Socket = Socket().also {
~>        it.connect(InetSocketAddress(server, port), 3000)
    }

    fun viaAddress(payload: ByteArray) {
        val address = InetSocketAddress(server, port)
        val socket = Socket()
~>        socket.connect(address, 5000)
        socket.getOutputStream().write(payload)
    }

    fun async() {
        val channel = AsynchronousSocketChannel.open()
~>        channel.connect(InetSocketAddress(server, port)).get()
    }

    fun asyncServer() {
~>        val listener = AsynchronousServerSocketChannel.open().bind(InetSocketAddress(port))
        listener.accept()
    }

    fun scopedServer(): ServerSocket = ServerSocket().apply {
        reuseAddress = true
~>        bind(InetSocketAddress(port))
    }
}
