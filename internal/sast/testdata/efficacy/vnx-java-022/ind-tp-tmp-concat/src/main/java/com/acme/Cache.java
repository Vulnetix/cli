package com.acme;
import java.io.File;
public class Cache {
    File forUser(String username) {
~>        return new File("/tmp/" + username + ".tmp");
    }
}
