package com.acme

import com.sun.net.httpserver.HttpServer
import com.sun.net.httpserver.HttpsServer
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.channels.ServerSocketChannel

fun startAdmin(adminPort: Int) {
    val adminTls = HttpsServer.create(InetSocketAddress(adminPort), 0)
    adminTls.start()
    val adminLocal = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), adminPort + 1), 0)
    adminLocal.start()
    val adminSocket = ServerSocket(adminPort + 2, 0, InetAddress.getByName("127.0.0.1"))
    adminSocket.close()
    val adminCh = ServerSocketChannel.open()
    adminCh.bind(InetSocketAddress("127.0.0.1", adminPort + 3))
    val publicCh = ServerSocketChannel.open()
    publicCh.bind(InetSocketAddress(8080))
}
