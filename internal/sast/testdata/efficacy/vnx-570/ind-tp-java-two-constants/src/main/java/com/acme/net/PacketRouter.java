package com.acme.net;

public final class PacketRouter {
    static final int TYPE_DATA = 1;
    static final int TYPE_PING = 2;

    int route(Packet packet) {
        int type = packet.type();
~>        if (type == TYPE_DATA && type == TYPE_PING) {
            return forwardWithAck(packet);
        }
        return forward(packet);
    }

    private int forward(Packet p) { return 0; }
    private int forwardWithAck(Packet p) { return 1; }
}
