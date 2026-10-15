package com.acme

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress

fun startManagement(config: Config) {
~>    val managementServer = HttpServer.create(InetSocketAddress(config.managementPort), 0)
    managementServer.createContext("/shutdown") { exchange -> shutdown(exchange) }
    managementServer.start()
}
