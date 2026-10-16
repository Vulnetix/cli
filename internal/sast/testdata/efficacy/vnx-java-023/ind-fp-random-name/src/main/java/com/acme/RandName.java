package com.acme;
import org.springframework.web.multipart.MultipartFile;
import java.io.File;
import java.util.UUID;
public class RandName {
    void save(MultipartFile f) throws Exception {
        f.transferTo(new File("/data/blobs/" + UUID.randomUUID()));
    }
}
