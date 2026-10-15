package com.example.auth;

import java.security.MessageDigest;

public class Etags {
    String etag(byte[] body) throws Exception {
        MessageDigest etagDigest = MessageDigest.getInstance("MD5");
        return toHex(etagDigest.digest(body));
    }

    String fileChecksum(byte[] body) throws Exception {
        MessageDigest checksum = MessageDigest.getInstance("MD5");
        return toHex(checksum.digest(body));
    }

    String websocketAccept(String key) throws Exception {
        // Sec-WebSocket-Accept is defined by RFC 6455 as SHA-1 of key + GUID.
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        return base64(sha1.digest((key + GUID).getBytes()));
    }
}
