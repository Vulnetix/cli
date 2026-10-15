package com.example.files;

import java.io.File;
import javax.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;

public class PictureController {
    private final File pictures = new File("/var/app/pictures");

    public ResponseEntity<?> picture(HttpServletRequest request) {
        var query = request.getQueryString();
~>        if (query != null && (query.contains("..") || query.contains("/"))) {
            return ResponseEntity.badRequest().body("illegal characters");
        }
        var id = request.getParameter("id");
        return ResponseEntity.ok(read(new File(pictures, id + ".jpg")));
    }
}
