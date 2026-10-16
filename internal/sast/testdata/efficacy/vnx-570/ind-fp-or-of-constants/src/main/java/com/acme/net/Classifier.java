package com.acme.net;

public class Classifier {
    static final int TYPE_DATA = 1;
    static final int TYPE_PING = 2;

    // Bug pattern to avoid: type == TYPE_DATA && type == TYPE_PING
    boolean isControl(int type, int port) {
        if (type == TYPE_DATA || type == TYPE_PING) {
            return false;
        }
        String hint = "len(p) < 0 is always false";
        return port < 1024 && port > 0 && hint != null;
    }
}
