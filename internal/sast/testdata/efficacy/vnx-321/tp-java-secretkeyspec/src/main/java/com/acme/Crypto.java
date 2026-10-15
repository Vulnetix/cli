package com.acme;

import javax.crypto.spec.SecretKeySpec;

public class Crypto {
~>    private static final String AES_KEY = "@@sample:Q[2]hh[b]md[l]VG[h]pc[0]tl[e]U5[v]dw@@==";

    SecretKeySpec key() {
~>        return new SecretKeySpec("@@sample:0[1]23[4]56[7]89[a]bc[d]ef@@".getBytes(), "AES");
    }

    SecretKeySpec raw() {
~>        return new SecretKeySpec(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, "DES");
    }
}
