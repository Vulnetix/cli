package app;

import java.util.Base64;

class Vault {
    String seal(Credentials creds) {
        byte[] secretBytes = creds.getPassword().getBytes();
~>        return Base64.getEncoder().encodeToString(secretBytes);
    }
}
