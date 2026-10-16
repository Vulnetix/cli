package com.acme.dedupe;

import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Set;

public class BlobStore {
    private final Set<String> knownHashes;

    public BlobStore(Set<String> knownHashes) { this.knownHashes = knownHashes; }

    public String store(byte[] blob) throws Exception {
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(blob));
        if (knownHashes.contains(hash)) {
            return hash;
        }
        String shard = hash.substring(0, 2);
        write(shard + "/" + hash, blob);
        knownHashes.add(hash);
        return hash;
    }

    private void write(String key, byte[] blob) { }
}
