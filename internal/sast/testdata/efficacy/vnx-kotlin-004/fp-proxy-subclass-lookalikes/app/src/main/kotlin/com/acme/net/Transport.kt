package com.acme.net

import android.bluetooth.BluetoothDevice
import android.net.LocalServerSocket
import android.net.LocalSocket
import java.net.DatagramSocket
import java.net.Proxy
import java.net.Socket
import javax.net.SocketFactory
import okhttp3.OkHttpClient
import okhttp3.Request

class Transport(private val proxy: Proxy, private val factory: SocketFactory) {
    fun viaSocks(): Socket = Socket(proxy)

    fun fromFactory(): Socket = factory.createSocket()

    fun fake(): Socket = object : Socket() {
        override fun isConnected() = true
    }

    fun local() {
        val local = LocalSocket()
        val server = LocalServerSocket("acme-agent")
    }

    fun bluetooth(device: BluetoothDevice) {
        val bt = device.createRfcommSocketToServiceRecord(SERVICE_UUID)
        bt.connect()
    }

    fun websocket(client: OkHttpClient) {
        val ws = client.newWebSocket(Request.Builder().url("wss://acme.io/ws").build(), Listener())
    }

    fun mySocket(host: String, port: Int) = buildSocket(host, port)
}

class FakeSocket : Socket()
