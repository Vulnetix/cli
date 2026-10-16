package com.acme.agent

import java.net.ServerSocket
import kotlin.concurrent.thread

class CommandListener(private val handler: CommandHandler) {
    fun start() {
~>        val server = ServerSocket(9090, 50)
        thread(name = "command-listener") {
            while (true) {
                val client = server.accept()
                handler.handle(client.getInputStream().bufferedReader().readLine(), client.getOutputStream())
                client.close()
            }
        }
    }
}
