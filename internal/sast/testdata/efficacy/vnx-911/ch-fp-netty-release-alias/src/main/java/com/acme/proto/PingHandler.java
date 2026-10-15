package com.acme.proto;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;
import java.nio.charset.StandardCharsets;

public class PingHandler extends ChannelInboundHandlerAdapter {
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        ByteBuf in = (ByteBuf) msg;
        try {
            if (in.readableBytes() > 0) {
                ctx.writeAndFlush(Unpooled.copiedBuffer("pong", StandardCharsets.US_ASCII));
            }
        } finally {
            ReferenceCountUtil.release(in);
        }
    }
}

class Relay extends ChannelInboundHandlerAdapter {
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        ctx.fireChannelRead(msg);
    }
}

class Forwarder extends ChannelInboundHandlerAdapter {
    private final io.netty.channel.Channel outbound;

    Forwarder(io.netty.channel.Channel outbound) {
        this.outbound = outbound;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        outbound.writeAndFlush(msg);
    }
}
