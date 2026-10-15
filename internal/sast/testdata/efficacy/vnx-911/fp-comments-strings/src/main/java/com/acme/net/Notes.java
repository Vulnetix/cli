package com.acme.net;

public class Notes {
    // refCount++ outside a lock races; channelRead(ChannelHandlerContext ctx, Object msg) must release
    private static final String HELP = "return Py_None; without Py_INCREF";

    public String help() {
        return HELP;
    }
}
