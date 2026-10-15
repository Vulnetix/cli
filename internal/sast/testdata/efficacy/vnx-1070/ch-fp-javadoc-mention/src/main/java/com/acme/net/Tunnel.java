package com.acme.net;

import java.net.Socket;

/**
 * Unlike Packet, which implements Serializable, a tunnel owns a live socket
 * and is never written to a stream.
 */
public class Tunnel {
    private Socket socket;
    private Thread reader;
}
