package com.acme.media;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import javax.imageio.ImageIO;

public class Thumbnailer {
    public BufferedImage load(String avatarUrl) throws IOException {
        URL url = new URL(avatarUrl);
~>        return ImageIO.read(url);
    }

    public byte[] raw(URI uri) throws IOException {
~>        try (InputStream in = uri.toURL().openStream()) {
            return in.readAllBytes();
        }
    }
}
