package com.acme.crypto;

import java.security.PrivateKey;
import javax.crypto.SecretKey;

public class Signer {
~>    public PrivateKey signingKey;
~>    public static SecretKey sessionKey;
~>    public char[] keystorePassword;
~>    public byte[]  secretBytes = new byte[32];
    private final String algorithm = "SHA256withRSA";
}
