package com.acme.media;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ThumbnailController {
    @GetMapping("/thumb")
    public String thumb(@RequestParam("file") String file) throws Exception {
        ProcessBuilder pb = new ProcessBuilder();
~>        pb.command("/bin/sh", "-c", "convert " + file + " -resize 64x64 /tmp/thumb.png");
        pb.start().waitFor();
        return "ok";
    }
}
