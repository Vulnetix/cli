package com.acme.net;

~>import static sun.nio.ch.DirectBuffer.*;
~>import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;

public class Resolver {
    public String decode(String s) throws Exception {
~>        byte[] b = new @@sample:s[u]n[.][m]is[c][.]B[A]SE[6]4D[e]co[d]er@@().decodeBuffer(s);
        return new String(b, "UTF-8");
    }

    public void clean(java.nio.ByteBuffer buf) {
~>        ((sun.nio.ch.DirectBuffer) buf).cleaner().clean();
    }
}
