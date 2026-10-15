package com.example.thumbs;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.net.URL;
import javax.imageio.ImageIO;

public class Thumbnailer {
    public BufferedImage fetch(String imageUrl) throws IOException {
        URL src = new URL(imageUrl);
~>        return ImageIO.read(src);
    }

    public BufferedImage fromDisk(java.io.File f) throws IOException {
        return ImageIO.read(f);
    }
}
