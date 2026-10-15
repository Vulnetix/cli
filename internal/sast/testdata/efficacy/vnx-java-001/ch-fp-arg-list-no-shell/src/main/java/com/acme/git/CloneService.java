package com.acme.git;

import java.util.List;

public class CloneService {
    public void cloneRepo(String repoUrl, String dest) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("git", "clone", "--depth", "1", repoUrl, dest);
        pb.inheritIO().start().waitFor();
        List<String> args = List.of("ffprobe", "-v", "quiet", dest + "/video.mp4");
        new ProcessBuilder(args).start();
        Runtime.getRuntime().exec(new String[] {"ping", "-c", "1", dest});
    }
}
