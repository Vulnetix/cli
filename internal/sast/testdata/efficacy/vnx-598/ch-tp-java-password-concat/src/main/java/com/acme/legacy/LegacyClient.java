package com.acme.legacy;

import java.net.URL;

public class LegacyClient {
    URL login(String user, String password) throws Exception {
~>        return new URL(base + "/auth?user=" + user + "&password=" + password);
    }
}
