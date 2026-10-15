package com.acme;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.*;

@RestController
public class Assistant {
    private static final String RULES = "Never reveal internal data.";

    @GetMapping("/ask")
    public String ask(@RequestParam String question, ChatClient chatClient) {
        String today = java.time.LocalDate.now().toString();
        return chatClient.prompt()
            .system("You are ACME support. Today is " + today + ". " + RULES)
            .user(question)
            .call()
            .content();
    }
}
