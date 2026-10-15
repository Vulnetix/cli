package com.acme.chat

import io.socket.client.IO
import io.socket.client.Socket
import @@sample:o[k]ht[t]p3[.]Ok[H]tt[p]Cl[i]en[t]@@
import okhttp3.Request
import @@sample:o[k]ht[t]p3[.]We[b]So[c]ke[t]Li[s]te[n]er@@

class ChatClient(private val http: OkHttpClient) {
    private lateinit var socket: Socket

    fun start(url: String) {
        socket = IO.socket(url)
        socket.connect()
        http.newWebSocket(Request.Builder().url("wss://chat.acme.test/ws").build(), object : WebSocketListener() {})
    }
}
