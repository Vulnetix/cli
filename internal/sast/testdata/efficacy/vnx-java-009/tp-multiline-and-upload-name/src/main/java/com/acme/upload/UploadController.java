package com.acme.upload;

import java.io.File;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

public class UploadController {
    private final File uploadDir = new File("/srv/uploads");

    @PostMapping("/upload")
    public String upload(@RequestParam("file") MultipartFile file) throws Exception {
~>        File dest = new File(uploadDir,
                file.getOriginalFilename());
        file.transferTo(dest);
        String id = request().getParameter("id");
        File picture =
~>            new File(uploadDir, (id == null ? "default" : id) + ".jpg");
        return picture.getPath();
    }

    private javax.servlet.http.HttpServletRequest request() {
        return null;
    }
}
