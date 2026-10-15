package com.acme.codec;

import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;

@Singleton
@Startup
public class CodecService {

    static {
~>        System.loadLibrary("acmecodec");
    }

    public byte[] encode(byte[] in) {
        return in;
    }
}
