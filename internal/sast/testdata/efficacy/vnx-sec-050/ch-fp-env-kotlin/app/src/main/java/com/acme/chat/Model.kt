package com.acme.chat

import com.google.ai.client.generativeai.GenerativeModel

val model = GenerativeModel(
    modelName = "gemini-1.5-flash",
    apiKey = BuildConfig.GEMINI_API_KEY
)
