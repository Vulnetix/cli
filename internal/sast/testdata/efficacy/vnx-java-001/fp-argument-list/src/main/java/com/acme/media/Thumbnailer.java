package com.acme.media;

import java.io.IOException;
import java.util.List;

public class Thumbnailer {
    public void make(String input, String output, String ref) throws IOException {
        new ProcessBuilder("convert", input, "-resize", "128x128", output).start();
        Runtime.getRuntime().exec(new String[] {"git", "log", ref + "..HEAD"});
        List<String> args = List.of("ffmpeg", "-i", input, output + ".mp4");
        new ProcessBuilder(args).start();
    }
}
