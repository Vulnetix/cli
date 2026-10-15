package net.acme.pos

import java.io.DataOutputStream
import java.net.InetAddress
import java.net.Socket

class Terminal(private val gatewayHost: String, private val port: Int) {
    fun authorize(pan: String, amount: Long) {
~>        val s = Socket(InetAddress.getByName(gatewayHost), port)
        DataOutputStream(s.getOutputStream()).use { out ->
            out.writeUTF(pan)
            out.writeLong(amount)
        }
    }
}
