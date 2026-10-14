package com.acme.files;

import java.io.File;
import javax.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PictureController {
    private final File pictures = new File("/srv/pictures");

    @GetMapping("/picture")
    public ResponseEntity<?> picture(HttpServletRequest request) throws Exception {
        var id = request.getParameter("id");
        var picture =
            new File(pictures, id + ".jpg");
        if (picture.exists()) {
~>            return ResponseEntity.ok().body(FileCopyUtils.copyToByteArray(picture));
        }
        return ResponseEntity.notFound().build();
    }
}
