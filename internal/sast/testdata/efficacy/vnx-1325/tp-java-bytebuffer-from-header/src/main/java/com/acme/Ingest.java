package com.acme;

import java.nio.ByteBuffer;
import javax.servlet.http.HttpServletRequest;

public class Ingest {
    public ByteBuffer accept(HttpServletRequest request) {
        int declared = request.getIntHeader("X-Payload-Length");
        long total = request.getContentLengthLong();
~>        ByteBuffer buf = ByteBuffer.allocate(declared);
~>        ByteBuffer direct = ByteBuffer.allocateDirect((int) total);
        return buf;
    }
}
