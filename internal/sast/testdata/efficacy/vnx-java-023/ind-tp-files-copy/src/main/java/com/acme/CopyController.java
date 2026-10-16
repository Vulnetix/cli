package com.acme;
import org.springframework.web.multipart.MultipartFile;
import java.nio.file.*;
public class CopyController {
    void save(MultipartFile mf) throws Exception {
        String name = mf.getOriginalFilename();
        Path dest = Paths.get("uploads", name);
~>        Files.copy(mf.getInputStream(), dest);
    }
}
