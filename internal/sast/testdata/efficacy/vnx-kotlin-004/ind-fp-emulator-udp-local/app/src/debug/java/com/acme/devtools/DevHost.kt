package com.acme.devtools

import android.net.LocalSocket
import android.net.LocalSocketAddress
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket

object DevHost {
    fun metro(): Socket = Socket("10.0.2.2", 8081)

    fun announce(group: InetAddress, payload: ByteArray) {
        DatagramSocket().use { it.send(DatagramPacket(payload, payload.size, group, 5353)) }
    }

    fun daemon(): LocalSocket = LocalSocket().apply { connect(LocalSocketAddress("acme_daemon")) }
}
