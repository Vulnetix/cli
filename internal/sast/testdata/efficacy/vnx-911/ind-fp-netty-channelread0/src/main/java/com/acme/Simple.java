package com.acme;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

public class Simple extends SimpleChannelInboundHandler<String> {
    private int count;

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, String msg) {
        count++;
    }
}
