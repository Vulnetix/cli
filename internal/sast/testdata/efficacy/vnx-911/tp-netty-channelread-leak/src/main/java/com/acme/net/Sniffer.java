package com.acme.net;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import java.nio.charset.StandardCharsets;

public class Sniffer extends ChannelInboundHandlerAdapter {
    @Override
~>    public void channelRead(final ChannelHandlerContext ctx, final Object frame)
            throws Exception {
        if (frame instanceof ByteBuf) {
            String text = ((ByteBuf) frame).toString(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@);
            System.out.println(text);
        }
    }
}
