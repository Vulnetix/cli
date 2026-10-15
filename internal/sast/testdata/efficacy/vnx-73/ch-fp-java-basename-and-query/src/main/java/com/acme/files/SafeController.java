package com.acme.files;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.apache.commons.io.FilenameUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SafeController {
    private final UserRepository users;

    public SafeController(UserRepository users) {
        this.users = users;
    }

    @GetMapping("/avatar")
    public byte[] avatar(@RequestParam String name) throws Exception {
        String safe = FilenameUtils.getName(name);
        return Files.readAllBytes(Paths.get("/srv/avatars", safe));
    }

    @GetMapping("/user")
    public User user(@RequestParam String email) throws Exception {
        Path cfg = Paths.get("/etc/app/users.yml");
        return users.findByEmail(email, Files.readString(cfg));
    }
}
