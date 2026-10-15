package com.acme.upload;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import org.springframework.web.multipart.MultipartFile;

public class UploadAudit {
    private final Path auditLog;
    private final Path store;

    public UploadAudit(Path auditLog, Path store) {
        this.auditLog = auditLog;
        this.store = store;
    }

    public void record(MultipartFile file) throws IOException {
        Path target = store.resolve(UUID.randomUUID().toString());
        file.transferTo(target);
        Files.write(auditLog, (file.getOriginalFilename() + " -> " + target + "\n").getBytes(@@sample:S[t]an[d]ar[d]Ch[a]rs[e]ts[.]UT[F][_]8@@),
                StandardOpenOption.APPEND);
    }
}
