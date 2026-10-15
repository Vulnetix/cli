package com.acme;

import java.security.Signature;

public class Sig {
    Signature s() throws Exception {
        return Signature.getInstance("SHA256withRSA");
    }
}
