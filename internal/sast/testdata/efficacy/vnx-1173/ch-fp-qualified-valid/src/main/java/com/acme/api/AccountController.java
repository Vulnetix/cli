package com.acme.api;

import org.springframework.web.bind.annotation.*;

@RestController
public class AccountController {

    @PostMapping("/accounts")
    public Account open(@jakarta.validation.Valid @RequestBody OpenAccount req) {
        return accounts.open(req);
    }

    @PutMapping("/accounts/{id}")
    public Account update(@PathVariable String id, @RequestBody @jakarta.validation.Valid UpdateAccount req) {
        return accounts.update(id, req);
    }

    @PostMapping("/accounts/{id}/notes")
    public void note(@PathVariable String id, @Valid @RequestBody NoteRequest note) {
        accounts.note(id, note);
    }

    @PostMapping("/accounts/{id}/raw")
    public void raw(@PathVariable String id, @RequestBody String json) {
        accounts.raw(id, json);
    }
}
