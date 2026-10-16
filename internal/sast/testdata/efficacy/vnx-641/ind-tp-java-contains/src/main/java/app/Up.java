package app;

import org.springframework.web.multipart.MultipartFile;

public class Up {
    boolean ok(MultipartFile file) {
        String fileName = file.getOriginalFilename();
~>        return fileName.contains(".pdf");
    }
}
