package com.acme.web;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class MediaController extends HttpServlet {
    private static final String MEDIA = "/srv/media";

    @GetMapping("/media")
    public ResponseEntity<InputStreamResource> media(@RequestParam String name) throws IOException {
~>        return ResponseEntity.ok().body(new InputStreamResource(new FileInputStream(MEDIA + "/" + name)));
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getPathInfo();
        File file = new File(MEDIA, path.substring(1));
~>        Files.copy(file.toPath(), resp.getOutputStream());
    }
}
