package com.acme.files;

import org.springframework.web.bind.annotation.PathVariable;

public class Docs {
    public String help(@PathVariable String filename) {
        // new FileSystemResource(uploadDir + filename) would expose every file
        String hint = "Avoid new FileSystemResource(uploadDir + filename)";
        return hint + filename;
    }
}
