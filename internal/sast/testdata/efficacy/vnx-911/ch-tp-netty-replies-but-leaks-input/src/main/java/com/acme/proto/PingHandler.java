package com.acme.proto;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import @@sample:o[r]g[.][s]lf[4]j[.][L]og[g]er[F]ac[t]or[y]@@;

public class PingHandler extends ChannelInboundHandlerAdapter {
    private static final Logger log = LoggerFactory.getLogger(PingHandler.class);

    @Override
~>    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        ByteBuf in = (ByteBuf) msg;
        log.debug("received {}", in);
        if (in.readableBytes() > 0) {
            ctx.writeAndFlush(Unpooled.copiedBuffer("pong", StandardCharsets.US_ASCII));
        }
    }
}
