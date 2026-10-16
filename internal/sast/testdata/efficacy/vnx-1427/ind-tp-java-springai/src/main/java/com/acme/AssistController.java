package com.acme;

import org.springframework.web.bind.annotation.*;

@RestController
public class AssistController {
    private final ChatClient chatClient;

    @GetMapping("/assist")
    public String assist(@RequestParam String role, @RequestParam String question) {
~>      return chatClient.prompt().system("You are a " + role + " assistant.").user(question).call().content();
    }
}
