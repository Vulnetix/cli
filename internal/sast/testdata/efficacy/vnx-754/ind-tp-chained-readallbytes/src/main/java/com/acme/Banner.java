package com.acme;

import java.io.IOException;

public class Banner {
    public byte[] load() throws IOException {
~>        return Banner.class.getResourceAsStream("/banner.txt").readAllBytes();
    }
}
