package app;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
public class DocController {
    private final DocRepository docRepository;
    public DocController(DocRepository r) { this.docRepository = r; }

    @PreAuthorize("@perm.canRead(#id)")
    @GetMapping("/docs/{id}")
    public Doc get(@PathVariable("id") Long id) {
        return docRepository.findById(id).orElseThrow();
    }

    // docRepository.findById(id) in a comment
    public Doc cached() { return null; }
}
