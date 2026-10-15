package com.acme.crypto;

import java.io.Serializable;
import java.security.PrivateKey;

~>public final class KeyHolder extends Holder<String>
        implements Serializable, Cloneable {
    private PrivateKey privateKey;
    private String alias;
}
