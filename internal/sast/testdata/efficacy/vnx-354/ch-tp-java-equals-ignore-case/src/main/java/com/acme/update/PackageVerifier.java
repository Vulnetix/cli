package com.acme.update;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

public final class PackageVerifier {

    public void verify(Path artifact, String expectedChecksum) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String actual = HexFormat.of().formatHex(md.digest(Files.readAllBytes(artifact)));
~>        if (expectedChecksum != null && !expectedChecksum.equalsIgnoreCase(actual)) {
            throw new SecurityException("checksum mismatch for " + artifact);
        }
        install(artifact);
    }

    private void install(Path artifact) {
    }
}
