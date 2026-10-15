package com.example.preview;

import java.io.InputStream;
import java.net.URL;

public class LinkPreview {
    public byte[] fetch(String link) throws Exception {
~>        try (InputStream in = new URL(link).openStream()) {
            return in.readNBytes(65536);
        }
    }

    public byte[] fetchUri(java.net.URI uri) throws Exception {
~>        try (InputStream in = uri.toURL().openStream()) {
            return in.readAllBytes();
        }
    }
}
