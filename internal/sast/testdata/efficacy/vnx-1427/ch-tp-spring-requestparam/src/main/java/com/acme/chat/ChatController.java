package com.acme.chat;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ChatController {
    private final ChatClient chatClient;

    ChatController(ChatClient.Builder b) { this.chatClient = b.build(); }

    @GetMapping("/chat")
    public String chat(@RequestParam String persona, @RequestParam String q) {
        return chatClient.prompt()
~>                .system(persona)
                .user(q)
                .call()
                .content();
    }
}
