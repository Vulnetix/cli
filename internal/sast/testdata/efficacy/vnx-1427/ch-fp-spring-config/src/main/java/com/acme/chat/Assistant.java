package com.acme.chat;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Assistant {
    @Value("${assistant.system-prompt}")
    private String systemPrompt;

    private final ChatClient chatClient;

    Assistant(ChatClient chatClient) { this.chatClient = chatClient; }

    @PostMapping("/ask")
    public String ask(@RequestBody String question) {
        return chatClient.prompt().system(systemPrompt).user(question).call().content();
    }
}
