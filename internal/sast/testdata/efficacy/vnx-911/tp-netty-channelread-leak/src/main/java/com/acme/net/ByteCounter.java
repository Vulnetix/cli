package com.acme.net;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

public class ByteCounter extends ChannelInboundHandlerAdapter {
    private long bytes;

    @Override
~>    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        ByteBuf in = (ByteBuf) msg;
        bytes += in.readableBytes();
    }
}
