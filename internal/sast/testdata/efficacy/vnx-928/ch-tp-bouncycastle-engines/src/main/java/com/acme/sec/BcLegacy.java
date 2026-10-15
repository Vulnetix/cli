package com.acme.sec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.DESedeEngine;
import @@sample:o[r]g[.][b]ou[n]cy[c]as[t]le[.]cr[y]pt[o][.]e[n]gi[n]es[.]RC[4]En[g]in[e]@@;
import org.bouncycastle.crypto.modes.CBCBlockCipher;

public class BcLegacy {
    BlockCipher block() {
~>        return new CBCBlockCipher(new DESedeEngine());
    }

    StreamCipher stream() {
~>        StreamCipher rc4 = new RC4Engine();
        return rc4;
    }
}
