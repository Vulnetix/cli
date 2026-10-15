package com.acme.dl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;

public class StaticFiles {
    private final Path base = Paths.get("/srv/static").toAbsolutePath().normalize();

    public byte[] serve(HttpServletRequest request) throws IOException {
        String name = request.getParameter("path");
        Path resolved = base.resolve(name).normalize();
        if (!resolved.startsWith(base)) {
            throw new SecurityException("outside of static root");
        }
        return Files.readAllBytes(resolved);
    }
}
