package com.acme.artifacts;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

public final class ArtifactVerifier {
    public void verify(Path file, String checksum) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] actual = md.digest(Files.readAllBytes(file));
        byte[] declared = checksum == null ? null : HexFormat.of().parseHex(checksum);
~>        if (checksum != null && !MessageDigest.isEqual(actual, declared)) {
            throw new SecurityException("checksum mismatch for " + file);
        }
        install(file);
    }

    private void install(Path file) { }
}
