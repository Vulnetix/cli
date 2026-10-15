package app;

import org.apache.commons.io.FilenameUtils;

public class Upload {
    public void save(MultipartFile file) {
        String ext = FilenameUtils.getExtension(file.getOriginalFilename());
        String name = file.getOriginalFilename();
        String last = name.substring(name.lastIndexOf(".") + 1);
        if (!name.toLowerCase().endsWith(".pdf")) {
            throw new IllegalArgumentException();
        }
    }
}
