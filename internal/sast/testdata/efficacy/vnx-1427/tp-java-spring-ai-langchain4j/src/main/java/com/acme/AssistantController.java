package com.acme;

import @@sample:d[e]v[.][l]an[g]ch[a]in[4]j[.][d]at[a][.]m[e]ss[a]ge[.]Sy[s]te[m]Me[s]sa[g]e@@;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.bind.annotation.*;

@RestController
public class AssistantController {
    private final ChatClient chatClient;

    AssistantController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @GetMapping("/assist")
    public String assist(@RequestParam String role, @RequestParam String question) {
        return chatClient.prompt()
~>            .system("You are a " + role + " assistant for ACME.")
            .user(question)
            .call()
            .content();
    }

    public SystemMessage persona(javax.servlet.http.HttpServletRequest request) {
        String persona = request.getParameter("persona");
~>        return SystemMessage.from(String.format("Act as %s.", persona));
    }

    public Object legacy(javax.servlet.http.HttpServletRequest request) {
~>        return new org.springframework.ai.chat.messages.SystemMessage("Rules: " + request.getParameter("rules"));
    }
}
