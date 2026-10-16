package com.acme.cache

import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket

object LocalRedis {
    fun ping(): String = Socket("127.0.0.1", 6379).use { s ->
        s.getOutputStream().write("PING\r\n".toByteArray())
        s.getInputStream().bufferedReader().readLine()
    }

    fun postgres(): Socket = Socket("localhost", 5432)

    fun callbackServer(): ServerSocket = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
}
