package com.acme.files;

import java.nio.file.Path;
import java.security.Principal;
import java.util.UUID;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class SecureDownloadController {
    private final Path uploadRoot = Path.of("/srv/uploads");
    private final FileRepository files;

    public SecureDownloadController(FileRepository files) { this.files = files; }

    @GetMapping("/download/{fileId}")
    public ResponseEntity<Resource> download(@PathVariable UUID fileId, Principal principal) {
        FileRecord record = files.findById(fileId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        if (!record.getOwner().equals(principal.getName())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        Path target = uploadRoot.resolve(record.getStoredName()).normalize();
        return ResponseEntity.ok(new FileSystemResource(target));
    }

    @PreAuthorize("hasPermission(#name, 'report', 'read')")
    @GetMapping("/reports/{name}")
    public ResponseEntity<Resource> report(@PathVariable String name) {
        return ResponseEntity.ok(new FileSystemResource(uploadRoot.resolve(name)));
    }

    @GetMapping("/mine/{name}")
    public ResponseEntity<Resource> mine(@PathVariable String name, Principal principal) {
        Path dir = uploadRoot.resolve(principal.getName());
        Path p = dir.resolve(name).normalize();
        if (!p.startsWith(dir)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        return ResponseEntity.ok(new FileSystemResource(p));
    }
}
