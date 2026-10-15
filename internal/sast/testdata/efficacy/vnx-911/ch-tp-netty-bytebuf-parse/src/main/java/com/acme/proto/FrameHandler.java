package com.acme.proto;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

public class FrameHandler extends ChannelInboundHandlerAdapter {
    @Override
~>    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        ByteBuf buf = (ByteBuf) msg;
        int type = buf.readByte();
        Dispatcher.handle(type, buf.readInt());
    }
}
