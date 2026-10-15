package com.acme.bc;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import @@sample:o[r]g[.][b]ou[n]cy[c]as[t]le[.]cr[y]pt[o][.]e[n]co[d]in[g]s[.][P]KC[S]1E[n]co[d]in[g]@@;
import org.bouncycastle.crypto.engines.RSAEngine;

public class BcWrap {
    public AsymmetricBlockCipher cipher() {
~>        return new PKCS1Encoding(new RSAEngine());
    }
}
