package com.acme.crypto;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;

public final class KeyHolder {
~>    public static KeyPair signingKeyPair;
~>    public javax.crypto.spec.SecretKeySpec hmacKey;
~>    public Map<String, String> secretsByEnv = new HashMap<>();

    public KeyHolder() {
    }
}
