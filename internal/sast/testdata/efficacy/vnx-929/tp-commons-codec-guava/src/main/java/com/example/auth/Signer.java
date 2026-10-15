package com.example.auth;

import com.google.common.hash.Hashing;
import org.apache.commons.codec.digest.DigestUtils;

public class Signer {
    String passwordHash(String password) {
~>        return DigestUtils.md5Hex(password);
    }

    String token(String user) {
~>        return DigestUtils.sha1Hex(user + System.nanoTime());
    }

    String guava(String password) {
~>        return Hashing.md5().hashString(password, @@sample:j[a]va[.]ni[o][.]c[h]ar[s]et[.]St[a]nd[a]rd[C]ha[r]se[t]s[.][U]TF[_]8@@).toString();
    }

    String guavaSha1(byte[] b) {
~>        return Hashing.sha1().hashBytes(b).toString();
    }
}
