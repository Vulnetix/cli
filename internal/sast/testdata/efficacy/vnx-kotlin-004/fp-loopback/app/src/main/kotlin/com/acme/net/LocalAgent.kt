package com.acme.net

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.aSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import kotlinx.coroutines.Dispatchers

class LocalAgent(private val port: Int) {
    fun redis() = Socket("127.0.0.1", 6379)

    fun local() = Socket("localhost", port)

    fun loop() = Socket(InetAddress.getLoopbackAddress(), port)

    fun emulatorHost() = Socket("10.0.2.2", port)

    fun control() = ServerSocket(0, 50, InetAddress.getLoopbackAddress())

    fun controlNamed() = ServerSocket(port, 10, InetAddress.getByName("127.0.0.1"))

    fun bound() {
        val s = Socket()
        s.connect(InetSocketAddress("localhost", port))
        val server = ServerSocket()
        server.bind(InetSocketAddress(InetAddress.getLoopbackAddress(), port))
    }

    suspend fun ktor() {
        val selector = SelectorManager(Dispatchers.IO)
        aSocket(selector).tcp().bind("127.0.0.1", 9002)
        aSocket(selector).tcp().connect("localhost", 9002)
    }
}

class LocalScoped(private val port: Int) {
    fun applied(): Socket = Socket().apply {
        connect(InetSocketAddress("127.0.0.1", port))
    }

    fun viaAddress() {
        val address = InetSocketAddress(InetAddress.getLoopbackAddress(), port)
        val socket = Socket()
        socket.connect(address)
    }

    fun scopedServer(): ServerSocket = ServerSocket().apply {
        bind(InetSocketAddress("localhost", port))
    }
}

class LocalByName(private val port: Int) {
    fun open(): Socket {
        val host = "localhost"
        return Socket(host, port)
    }

    fun listen(): ServerSocket {
        val bindAddress = InetAddress.getLoopbackAddress()
        return ServerSocket(port, 50, bindAddress)
    }
}
