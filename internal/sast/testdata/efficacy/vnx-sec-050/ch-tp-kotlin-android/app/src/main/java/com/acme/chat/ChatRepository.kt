package com.acme.chat

import com.google.ai.client.generativeai.GenerativeModel

class ChatRepository {
    private val model = GenerativeModel(
        modelName = "gemini-1.5-flash",
~>        apiKey = "AIza@@sample:[0-9A-Za-z_-]{35}@@"
    )
}
