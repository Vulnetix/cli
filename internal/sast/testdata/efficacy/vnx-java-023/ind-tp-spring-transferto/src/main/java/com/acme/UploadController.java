package com.acme;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.File;
@RestController
public class UploadController {
    @PostMapping("/upload")
    public String up(@RequestParam("file") MultipartFile file) throws Exception {
~>        file.transferTo(new File("/var/www/uploads/" + file.getOriginalFilename()));
        return "ok";
    }
}
