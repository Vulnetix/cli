package com.acme

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress

fun startOps(mgmtPort: Int) {
~>    val server = HttpServer.create(InetSocketAddress("0.0.0.0", mgmtPort), 0)
    server.createContext("/ops", OpsHandler())
    server.start()
}
